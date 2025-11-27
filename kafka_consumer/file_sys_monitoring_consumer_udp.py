# from kafka import KafkaConsumer
import json
import psycopg2
import socket
import logging
LOG = logging.getLogger("File System Monitoring Consumer")
import time
from dataclasses import asdict
from collections import defaultdict, deque
import os

from helper import store_anomaly_to_database_and_siem, store_siem_ready_packet, build_file_sys_moni_packet

CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
# UDP_PORT = config["udp"]["server_port"]
UDP_PORT = 6005



sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((UDP_IP, UDP_PORT))

DB_CONFIG = {
    'host': config["local_db"]["host"],
    'user': config["local_db"]["user"],
    'password': config["local_db"]["password"],
    'dbname': config["local_db"]["dbname"]
}

def load_sensitive_directories_from_db():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("SELECT sensitive_files FROM anomalous_file_access_config LIMIT 1;")
        row = cur.fetchone()
        cur.close()
        conn.close()

        if row and row[0]:
            # keep only directories that exist
            return [d for d in row[0] if os.path.exists(d)]

        return []

    except Exception as e:
        LOG.error(f"Failed loading sensitive dirs from DB: {e}")
        return []
    
sensitive_dirs = load_sensitive_directories_from_db()

# anomaly detection state
# sensitive_dirs = [d for d in config.get("sensitive_dirs", []) if os.path.exists(d)]
# 2️⃣ Fallback: config.json
if not sensitive_dirs:
    sensitive_dirs = [d for d in config.get("sensitive_dirs", []) if os.path.exists(d)]
    # if sensitive_dirs:
    #     print("[INFO] Loaded sensitive dirs from config.json")
    # else:
    #     print("[WARNING] No sensitive directories found in DB or config.json")
        
file_access_log = defaultdict(lambda: deque(maxlen=20))
# FREQ_THRESHOLD = 10
FREQ_THRESHOLD = config.get("frequency_anomaly", {}).get("threshold", 10)
# FREQ_WINDOW = 60  # seconds
FREQ_WINDOW = config.get("frequency_anomaly", {}).get("window_seconds", 60)

directory_access_log = defaultdict(lambda: deque(maxlen=200))

DIR_FREQ_THRESHOLD = config.get("frequency_anomaly", {}).get("directory_threshold", 10)


import string

# ---------------- Baseline Rules ----------------
# PROTECTED_DIRS = ["/etc", "/bin", "/usr"]
PROTECTED_DIRS = sensitive_dirs

def baseline_ok(evt):
    """
    Check whether the file operation satisfies baseline rules.
    Returns (True, None) if safe/normal.
    Returns (False, reason) if violation.
    """
    etype = evt["metrics"].get("event_type")
    path  = evt["metrics"].get("directory", "")
    fname = os.path.basename(path)

    if not fname:
        return False, "Empty filename"

    first_char = fname[0]

    # --- Creation rules ---
    if etype == "created":
        if first_char.isdigit():
            return False, "Filename starts with a number"
        if first_char in string.punctuation or first_char in ["_", ".", "-"]:
            return False, f"Filename starts with special character: {first_char}"

    # --- Modification rules ---
    if etype == "modified":
        # baseline: allow all modifications for now
        pass

    # --- Deletion rules ---
    if etype == "deleted":
        if any(path.startswith(d) for d in PROTECTED_DIRS):
            return False, f"Deletion not allowed in {path}"

    # --- Move rules ---
    if etype == "moved":
        dest = evt.get("event_info", {}).get("Value", {}).get("to", "")
        if dest and not os.access(os.path.dirname(dest), os.W_OK):
            return False, f"Move target not writable: {dest}"

    return True, None

def baseline_deviation(evt):
    ok, reason = baseline_ok(evt)
    return (not ok), reason
# ------------------------------------------------


def is_sensitive(path):
    return any(path.startswith(sd) for sd in sensitive_dirs)

last_freq_alert = {}

def is_access_frequency_anomalous(path):
    now = time.time()
    access_times = file_access_log[path]
    access_times.append(now)

    recent = [t for t in access_times if now - t <= FREQ_WINDOW]
    count = len(recent)

    # cooldown logic
    last_alert = last_freq_alert.get(path, 0)
    cooldown_over = (now - last_alert) > FREQ_WINDOW

    if count > FREQ_THRESHOLD and cooldown_over:
        last_freq_alert[path] = now
        return True, count

    return False, count

def is_directory_frequency_anomalous(directory):
    now = time.time()
    access_times = directory_access_log[directory]
    access_times.append(now)

    recent = [t for t in access_times if now - t <= FREQ_WINDOW]
    count = len(recent)

    # cooldown per directory
    last_alert = last_freq_alert.get(f"dir:{directory}", 0)
    cooldown_over = (now - last_alert) > FREQ_WINDOW

    if count > DIR_FREQ_THRESHOLD and cooldown_over:
        last_freq_alert[f"dir:{directory}"] = now
        return True, count

    return False, count



def store_file_event(evt):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # Ensure table exists with log_text added
        cur.execute("""
            CREATE TABLE IF NOT EXISTS file_system_monitoring (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ,
                username TEXT,
                hostname TEXT,
                mac_address TEXT,
                directory TEXT,
                event_type TEXT,
                log_text TEXT
            )
        """)

        # -------- build log_text --------
        event_type = evt["metrics"].get("event_type")
        directory = evt["metrics"].get("directory")

        log_text = None

        value = evt.get("event_info", {}).get("Value")

        if event_type == "renamed":
            # rename always src → dest
            src = value.get("from")
            dest = value.get("to")
            log_text = f"File renamed: {src} → {dest}"

        elif event_type == "moved":
            src = value.get("from")
            dest = value.get("to")
            log_text = f"File moved: {src} → {dest}"

        else:
            log_text = f"File event '{event_type}' occurred on {directory}"

        # -------- insert event --------
        cur.execute("""
            INSERT INTO file_system_monitoring (
                timestamp, username, hostname, mac_address, directory, event_type, log_text
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            evt['timestamp'],
            evt.get('username'),
            evt['metrics'].get('hostname'),
            evt['metrics'].get('mac_address'),
            directory,
            event_type,
            log_text
        ))

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        print(f"[ERROR] Failed to log event: {e}")
        LOG.error(f"Failed to log file event: {e}")


def main(stop_event=None):
    print("\033[1;92m!!!!!!!!! File System Monitoring Consumer running (UDP) !!!!!!\033[0m")
    LOG.info("!!!!!!!!! File System Monitoring Consumer running (UDP) !!!!!!")

    # Normal events → for non-sensitive dirs
    event_name_mapping = {
        "created": "FILE_CREATED",
        "modified": "FILE_WRITE",
        "deleted": "FILE_DELETE",
        "moved": "FILE_MOVED",
        "renamed": "FILE_RENAMED",
        "open": "FILE_READ"
    }

    # Sensitive dir override mapping
    SENSITIVE_MAPPING = {
        "created": "SENSITIVE_FILE_CREATE",
        "modified": "SENSITIVE_FILE_MODIFY",
        "deleted": "SENSITIVE_FILE_DELETE",
        "attrib_change": "SENSITIVE_FILE_PERMISSION_CHANGE",
        "open": "SENSITIVE_FILE_READ",
        "access_denied": "ACCESS_DENIED",
        "upload": "FILE_UPLOAD",
        "download": "FILE_DOWNLOAD"
    }

    ignore_list = {"close_nowrite"}   # only this event ignored unless freq anomaly

    try:
        while not (stop_event and stop_event.is_set()):
            data, addr = sock.recvfrom(65535)
            evt = json.loads(data.decode("utf-8"))

            if evt.get("topic") != "sensitive-events":
                continue

            # Print for debugging
            print(f"[CONSUMED EVENT from {addr}]\n{json.dumps(evt, indent=2)}")

            # Extract fields
            path = evt["metrics"].get("directory", "")
            etype = evt["metrics"].get("event_type", "")

            sensitive_hit = is_sensitive(path)

            # FREQUENCY anomaly (applies everywhere)
            freq_anomaly, freq_count = is_access_frequency_anomalous(path)

            dir_anomaly, dir_freq_count = is_directory_frequency_anomalous(os.path.dirname(path))


            # Special case: file moved INTO sensitive folder
            special_moved_to_sensitive = (etype == "moved" and sensitive_hit)

            # ALWAYS store raw event
            store_file_event(evt)

            # ---------------- Collect anomalies (can be multiple) ----------------
            anomalies = []

            # 1. Sensitive directory anomaly
            if sensitive_hit:
                if etype in SENSITIVE_MAPPING:
                    anomalies.append({
                        "mapped_event_name": SENSITIVE_MAPPING[etype],
                        "event_type": "FILE_AND_OBJECT_ACCESS_EVENTS",
                        "event_reason": f"{SENSITIVE_MAPPING[etype]} detected in sensitive directory"
                    })

            # 1A. Special case: move → sensitive == sensitive create
            if special_moved_to_sensitive:
                anomalies.append({
                    "mapped_event_name": "SENSITIVE_FILE_CREATE",
                    "event_type": "FILE_AND_OBJECT_ACCESS_EVENTS",
                    "event_reason": "File moved into sensitive directory"
                })

            # 2. FREQUENCY anomaly (independent, applies everywhere)
            if freq_anomaly:
                anomalies.append({
                    "mapped_event_name": "ANOMALOUS_FILE_ACCESS",
                    "event_type": "BEHAVIORAL_EVENTS",
                    "event_reason": f"File accessed {freq_count} times in {FREQ_WINDOW}s"
                })

            # 3. DIRECTORY-LEVEL frequency anomaly
            if dir_anomaly:
                anomalies.append({
                    "mapped_event_name": "ANOMALOUS_FILE_ACCESS",
                    "event_type": "BEHAVIORAL_EVENTS",
                    "event_reason": (
                        f"{dir_freq_count} file operations in directory "
                        f"{os.path.dirname(path)} within {FREQ_WINDOW}s"
                    )
                })


            # If no anomalies → nothing more to do
            if not anomalies:
                continue

            # ---------------- Emit all anomalies ----------------
            for anomaly_info in anomalies:

                anomaly = {
                    "msg_id": "UEBA_SIEM_FILE_SYS_MONI_MSG",
                    "event_type": anomaly_info["event_type"],
                    "event_name": anomaly_info["mapped_event_name"],
                    "event_reason": anomaly_info["event_reason"],
                    "timestamp": evt.get("timestamp"),

                    "log_text": json.dumps(evt, default=str),
                    "severity": "ALERT",

                    "username": evt.get("username"),
                    "device_hostname": evt["metrics"].get("hostname"),
                    "device_mac_id": evt["metrics"].get("mac_address"),

                    "file_name": evt["metrics"].get("file_name", "N/A"),
                    "file_path": path,

                    "frequency_count": freq_count,
                    "operation_type": etype,
                }

                try:
                    store_anomaly_to_database_and_siem(anomaly)

                    siem_packet = build_file_sys_moni_packet(anomaly)
                    store_siem_ready_packet(asdict(siem_packet))

                except Exception as e:
                    LOG.error(f"Failed to process file anomaly: {e}")

    except KeyboardInterrupt:
        print("\nConsumer stopped by user.")
    except Exception as e:
        LOG.error(f"UDP consumer error: {e}")
    finally:
        sock.close()
        LOG.info("UDP consumer closed.")



if __name__ == "__main__":
    main()
