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

# anomaly detection state
sensitive_dirs = [d for d in config.get("sensitive_dirs", []) if os.path.exists(d)]
file_access_log = defaultdict(lambda: deque(maxlen=20))
FREQ_THRESHOLD = 10
FREQ_WINDOW = 60  # seconds

import string

# ---------------- Baseline Rules ----------------
PROTECTED_DIRS = ["/etc", "/bin", "/usr"]

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

def is_access_frequency_anomalous(path):
    now = time.time()
    access_times = file_access_log[path]
    access_times.append(now)
    recent = [t for t in access_times if now - t <= FREQ_WINDOW]
    return len(recent) > FREQ_THRESHOLD, len(recent)


def store_file_event(evt):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS file_system_monitoring (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ,
                username TEXT,
                hostname TEXT,
                mac_address TEXT,
                directory TEXT,
                event_type TEXT
            )
        """)
        cur.execute("""
            INSERT INTO file_system_monitoring (
                timestamp, username, hostname, mac_address, directory, event_type
            ) VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            evt['timestamp'],
            evt.get('username'),
            evt['metrics'].get('hostname'),
            evt['metrics'].get('mac_address'),
            evt['metrics'].get('directory'),
            evt['metrics'].get('event_type'),
        ))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Failed to log event: {e}")
        LOG.error("Failed to log file event: %s", e)


def main(stop_event=None):
    print("\033[1;92m!!!!!!!!! File System Monitoring Consumer Running (UDP) !!!!!!\033[0m")
    LOG.info("!!!!!!!!! File System Monitoring Consumer Running (UDP) !!!!!!")


    # map raw watchdog events → SOC style strings
    event_name_mapping = {
        "created": "FILE_WRITE",
        "modified": "FILE_WRITE",
        "deleted": "FILE_DELETE",
        "moved": "FILE_PERMISSION_CHANGE"
    }

    try:
        while not (stop_event and stop_event.is_set()):
            data, addr = sock.recvfrom(65535)
            evt = json.loads(data.decode("utf-8"))

            if evt.get("topic") == "sensitive-events":
                LOG.info(
                    "[FSM received] dir=%s event=%s file=%s host=%s",
                    evt.get("metrics", {}).get("directory"),
                    evt.get("metrics", {}).get("event_type"),
                    evt.get("metrics", {}).get("file_name"),
                    evt.get("metrics", {}).get("hostname"),
                )
                print(f"[CONSUMED EVENT from {addr}]\n{json.dumps(evt, indent=2)}")

                path = evt["metrics"].get("directory", "")
                # freq_anomaly, freq_count = is_access_frequency_anomalous(path)
                freq_anomaly, freq_count = is_access_frequency_anomalous(path)
                rule_violation, rule_reason = baseline_deviation(evt)
                anomaly_flag = is_sensitive(path) or freq_anomaly or rule_violation

                anomaly_flag = is_sensitive(path) or freq_anomaly
                if anomaly_flag:
                    LOG.info(
                        "[FSM anomaly] dir=%s event=%s sensitive=%s freq=%s",
                        path,
                        evt["metrics"].get("event_type", "NA"),
                        is_sensitive(path),
                        freq_count,
                    )

                # Log all file events (keeps raw event_type: created/modified/deleted/moved)
                store_file_event(evt)

                if anomaly_flag:
                    raw_event_type = evt["metrics"].get("event_type", "NA")
                    mapped_event_name = event_name_mapping.get(raw_event_type, "NA")

                    anomaly = {
                        "msg_id": "UEBA_SIEM_FILE_SYS_MONI_MSG",
                        "event_type": "FILE_AND_OBJECT_ACCESS_EVENTS",
                        # anomalies_log.event_subtype will show FILE_WRITE / FILE_DELETE etc.
                        "event_name": mapped_event_name,
                        # "event_reason": f"{mapped_event_name} detected in sensitive directory",
                        "event_reason": rule_reason or (
                            f"{mapped_event_name} detected in sensitive directory" if is_sensitive(path)
                            else f"Frequency anomaly: {freq_count} accesses in {FREQ_WINDOW}s"
                        ),
                        "timestamp": evt.get("timestamp"),
                        "log_text": json.dumps(evt, default=str),
                        "severity": "ALERT",
                        "username": evt.get("username"),
                        "device_hostname": evt["metrics"].get("hostname"),
                        "device_mac_id": evt["metrics"].get("mac_address"),
                        "file_name": evt["metrics"].get("file_name", "N/A"),
                        "file_path": path,
                        # keep raw value for reference
                        # "operation_type": raw_event_type,
                        "frequency_count": freq_count,
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
