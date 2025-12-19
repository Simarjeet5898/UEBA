import json
import socket
# from kafka import KafkaConsumer
# from SIEM_connector import create_packet, load_config ,send_json_packet
# from SIEM_connector import create_packet ,send_json_packet
# from store_anomaly import store_anomaly
import os 
# import sys
# from datetime import datetime,timedelta
from datetime import datetime, timedelta, timezone
# import mysql.connector
import psycopg2
# from db_send import store_anomaly_to_postgres
from dataclasses import asdict
from helper import store_anomaly_to_database_and_siem,store_siem_ready_packet
import socket
from helper import build_command_exe_moni_packet,build_anomalous_cpu_gpu_ram_consp_packet
from helper import build_anomalous_cpu_consumption_packet,build_anomalous_ram_consumption_packet,build_anomalous_gpu_consumption_packet
# from udp_dispatcher import queues
import math
from datetime import datetime
import logging
LOG = logging.getLogger("SRU Consumer")


from collections import defaultdict

anomaly_last_seen = defaultdict(lambda: datetime.min)
ANOMALY_COOLDOWN = timedelta(minutes=0)


# Database configuration

CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
# UDP_PORT = config["udp"]["server_port"]

# SRU consumer internal port
UDP_PORT = 6004  

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((UDP_IP, UDP_PORT))

DB_CONFIG = {
    'host': config["local_db"]["host"],
    'user': config["local_db"]["user"],
    'password': config["local_db"]["password"],
    'dbname': config["local_db"]["dbname"]
}

destinations = config["destinations"]
anom_conf = config.get("anomalous_cpu_gpu_ram_anomaly", {})




SENSITIVE_COMMANDS = {
    # Privilege escalation / identity switching
    "sudo", "su", "eval", "exec", "source",

    # Password and user management
    "passwd", "useradd", "adduser", "usermod", "userdel",

    # Service and system control
    "systemctl", "service", "init", "rc.d",
    "shutdown", "reboot", "halt", "poweroff",
    "taskkill", "Stop-Process",

    # Dangerous deletions or permission changes
    "rm", "chmod", "chown",

    # Disk / partition management
    "mkfs", "dd",

    # Remote access / file transfer
    "ssh", "scp", "rsync", "sftp",

    # Download/upload tools
    "wget", "curl", "ftp", "tftp",

    # Networking / sockets
    "netstat", "ss", "lsof", "nc", "ncat", "socat", "openssl",

    # PowerShell / remote execution
    "Invoke-WebRequest", "Invoke-Expression",

    # Process monitoring / enumeration
    "ps", "top", "htop", "tasklist",

    # Obfuscation / encoding tools
    "base64", "xxd", "openssl",

    # Shells and script files
    "bash", "sh", ".sh", ".ps1",

    # Potentially repeated entries (ensure deduplication)
    # Note: "scp", "ftp", "curl", "wget" already included above

    # Special patterns (handled via logic, not names)
    "rm -rf /",  # Dangerous full wipe
}


# EWMA Settings
ALPHA = 0.4  # EWMA smoothing factor
SIGMA_THRESHOLD = 2 

ewma_metrics = {}
ewma_deviation = {}


ANOMALY_CATEGORIES = {
    "cpu_usage": {
        "Event Type": "BEHAVIORAL_EVENTS",
        "Event Sub Type": "ANOMALOUS_CPU_CONSUMPTION",
        "Event Details": "Excessive CPU utilization detected",
    },
    "memory_usage": {
        "Event Type": "BEHAVIORAL_EVENTS",
        "Event Sub Type": "ANOMALOUS_RAM_CONSUMPTION",
        "Event Details": "Unusual memory usage indicating potential attack",
    },
    "gpu_usage": {
        "Event Type": "BEHAVIORAL_EVENTS",
        "Event Sub Type": "ANOMALOUS_GPU_CONSUMPTION",
        "Event Details": "Unexpected GPU usage",
    }

}

def update_ewma(current_value, prev_ewma):
    """Compute EWMA: EWMA_t = α * X_t + (1 - α) * EWMA_(t-1)"""
    return ALPHA * current_value + (1 - ALPHA) * prev_ewma if prev_ewma is not None else current_value


def detect_anomalies(metrics):
    """Detect anomalies using device-specific EWMA and deviation-based thresholding."""
    global ewma_metrics, ewma_deviation
    anomalies = []

    # Use MAC address as the primary identifier instead of username
    mac_address = metrics.get("mac_address", "Unknown-MAC")
    
    # Initialize dictionaries for new MAC addresses
    if mac_address not in ewma_metrics:
        ewma_metrics[mac_address] = {}
        ewma_deviation[mac_address] = {}

    # Extract only numeric metrics
    numeric_metrics = {
        key: float(value)
        for key, value in metrics.items()
        if isinstance(value, (int, float))
    }

    # For new devices, just store initial values
    if not ewma_metrics[mac_address]:
        ewma_metrics[mac_address] = {key: numeric_metrics[key] for key in numeric_metrics}
        ewma_deviation[mac_address] = {key: 0 for key in numeric_metrics}
        return []

    for key, value in numeric_metrics.items():
        # Skip specific metrics below their thresholds
        if (key == "gpu_usage" and value < 9) or \
           (key == "disk_read_rate" and value < 190000000) or \
           (key == "disk_write_rate" and value < 190000000):
            # Still update EWMA for tracking but don't trigger anomaly
            if key in ewma_metrics[mac_address]:
                ewma_metrics[mac_address][key] = update_ewma(value, ewma_metrics[mac_address][key])
                ewma_deviation[mac_address][key] = update_ewma(0, ewma_deviation[mac_address][key])
            else:
                ewma_metrics[mac_address][key] = value
                ewma_deviation[mac_address][key] = 0
            continue

        if key not in ewma_metrics[mac_address]:
            ewma_metrics[mac_address][key] = value
            ewma_deviation[mac_address][key] = 0
            continue

        prev_ewma = ewma_metrics[mac_address][key]
        new_ewma = update_ewma(value, prev_ewma)
        deviation = abs(value - prev_ewma)
        new_deviation = update_ewma(deviation, ewma_deviation[mac_address][key])
        threshold = SIGMA_THRESHOLD * new_deviation

        # Different ratio triggers for different metrics
        if key == "cpu_usage":
            ratio_trigger = 1.2   # CPU: +20% jump
        elif key == "memory_usage":
            ratio_trigger = 1.3   # Memory: +30% jump
        elif key == "gpu_usage":
            ratio_trigger = 1.25  # GPU: +25% jump
        else:
            ratio_trigger = 1.8   # Others stay stricter

        if (deviation > threshold and (prev_ewma > 0 and (value / prev_ewma) > ratio_trigger)):
            key_tuple = (mac_address, key)
            now = datetime.now()

            if now - anomaly_last_seen[key_tuple] > ANOMALY_COOLDOWN:
                anomaly_info = ANOMALY_CATEGORIES.get(key, {
                    "Event Type": "Unknown",
                    "Event Sub Type": "Unknown",
                    "Event Details": "No details available",
                })
                anomalies.append({
                    "metric": key,
                    "Value": value,
                    "ewma": round(prev_ewma, 2),
                    "Event Type": anomaly_info["Event Type"],
                    "Event Sub Type": anomaly_info["Event Sub Type"],
                    "Event Details": anomaly_info["Event Details"]
                })
                anomaly_last_seen[key_tuple] = now

        # update state
        ewma_metrics[mac_address][key] = new_ewma
        ewma_deviation[mac_address][key] = new_deviation

    return anomalies

def detect_anomalous_resource_usage(metrics):
    """
    Detect anomalies ONLY for CPU, Memory, and GPU.
    No cooldown, no EWMA. Uses simple thresholds + persistence + recovery.
    With debug prints for behavior tracing.
    """

    # WATCHED = {
    #     "cpu_usage":    {"min_abs": 75.0, "event_name": "Anomalous CPU Usage"},
    #     "memory_usage": {"min_abs": 65.0, "event_name": "Anomalous Memory Usage"},
    #     "gpu_usage":    {"min_abs": 15.0, "event_name": "Anomalous GPU Usage"},
    # }
    # PERSISTENCE_REQUIRED = 3   # consecutive abnormal samples to trigger
    # RECOVERY_REQUIRED    = 3   # consecutive normal samples to reset

    WATCHED = {
        "cpu_usage": {
            "min_abs": anom_conf.get("cpu_threshold", 75),
            "event_name": "Anomalous CPU Usage"
        },
        "memory_usage": {
            "min_abs": anom_conf.get("memory_threshold", 65),
            "event_name": "Anomalous Memory Usage"
        },
        "gpu_usage": {
            "min_abs": anom_conf.get("gpu_threshold", 15),
            "event_name": "Anomalous GPU Usage"
        }
    }

    PERSISTENCE_REQUIRED = anom_conf.get("persistence_required", 3)
    RECOVERY_REQUIRED    = anom_conf.get("recovery_required", 3)
    # persistent state per device
    ru_state = globals().setdefault("_RU_STATE_SIMPLE", {})

    mac = metrics.get("mac_address", "Unknown-MAC")
    host = metrics.get("hostname")
    user = metrics.get("username")
    ts   = metrics.get("timestamp")

    mstate = ru_state.setdefault(mac, {
        "strikes": {}, "recovery": {}, "active": {}
    })

    anomalies = []

    for key, cfg in WATCHED.items():
        v = metrics.get(key, None)
        if not isinstance(v, (int, float)):
            continue

        if key not in mstate["strikes"]:
            mstate["strikes"][key] = 0
            mstate["recovery"][key] = 0
            mstate["active"][key] = False

        # abnormal condition
        abnormal = v >= cfg["min_abs"]

        if abnormal:
            mstate["strikes"][key] += 1
            mstate["recovery"][key] = 0

            if not mstate["active"][key] and mstate["strikes"][key] >= PERSISTENCE_REQUIRED:
                # fire anomaly once at episode start
                mstate["active"][key] = True
                mstate["strikes"][key] = 0

                print(f"[ALERT] {cfg['event_name']} fired for {mac} at {ts} (value={v:.2f})")

                anomalies.append({
                    "event_type": "SYSTEM_EVENTS",
                    "event_name": cfg["event_name"],
                    "event_reason": f"{cfg['event_name']} detected: value={v:.2f}%",
                    "metric": key,
                    "current_value": v,
                    "mac_address": mac,
                    "hostname": host,
                    "username": user,
                    "timestamp": ts,
                    "severity": "ALERT",
                })
        else:
            mstate["strikes"][key] = 0
            if mstate["active"][key]:
                mstate["recovery"][key] += 1
                if mstate["recovery"][key] >= RECOVERY_REQUIRED:
                    print(f"[INFO] {cfg['event_name']} recovered for {mac} at {ts}")
                    mstate["active"][key] = False
                    mstate["recovery"][key] = 0

    return anomalies


# One-time table creation & migration before the loop
conn = psycopg2.connect(**DB_CONFIG)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS executed_commands_ueba (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP,
    username TEXT,
    source TEXT,
    command TEXT,
    mac_address TEXT,
    ip_address TEXT
);
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS resource_usage_ueba (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    username VARCHAR(100),
    mac_address VARCHAR(50),
    ip_addresses TEXT,
    cpu_usage FLOAT,
    gpu_usage FLOAT,
    ram_usage FLOAT,
    memory_usage FLOAT,
    disk_read_rate FLOAT,
    disk_write_rate FLOAT,
    network_bytes_sent BIGINT,
    network_bytes_recv BIGINT,
    network_packets_sent BIGINT,
    network_packets_recv BIGINT,
    top_process_pid INTEGER,
    top_process_name VARCHAR(255),
    top_process_rss BIGINT
);
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS network_status_ueba (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    username VARCHAR(100),
    mac_address VARCHAR(50),
    interface_name VARCHAR(100),
    connection_status VARCHAR(50),
    latency_ms FLOAT,
    ip_address VARCHAR(100),        
    ping_ok BOOLEAN,
    mtu INTEGER,
    duplex INTEGER,
    bytes_sent BIGINT,
    bytes_recv BIGINT,
    gateway_ip VARCHAR(100),
    is_up BOOLEAN,
    speed_mbps INTEGER,
    snapshot_date DATE DEFAULT CURRENT_DATE
);
""")


conn.commit()
cur.close()
conn.close()


def get_command_baseline(username, min_samples=20):
    """
    Build a baseline profile of user command usage.
    Falls back to SENSITIVE_COMMANDS if not enough history.
    """
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        cur.execute("""
            SELECT command
            FROM executed_commands_ueba
            WHERE username = %s
            ORDER BY timestamp DESC
            LIMIT 100;
        """, (username,))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        if len(rows) < min_samples:
            # Not enough history → fallback
            return {"mode": "default", "sensitive": SENSITIVE_COMMANDS}

        # Flatten and normalize commands
        commands = [r[0].split()[0] for r in rows if r and r[0]]
        freq = {}
        for c in commands:
            freq[c] = freq.get(c, 0) + 1

        top_common = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:20]

        baseline = {
            "mode": "learned",
            "common_commands": {cmd: count for cmd, count in top_common},
            "sensitive_seen": [c for c in commands if c in SENSITIVE_COMMANDS],
            "total_count": len(commands)
        }
        return baseline

    except Exception as e:
        LOG.error(f"[Baseline] Failed for {user_id}: {e}")
        return {"mode": "default", "sensitive": SENSITIVE_COMMANDS}

def detect_command_deviation(user_id, command, baseline):
    """
    Decide if a command deviates from the baseline.
    Returns anomaly dict if deviation detected, else None.
    """
    cmd_base = command.split()[0] if command else ""
    now = datetime.now(timezone.utc).isoformat()

    if baseline["mode"] == "default":
        # Cold start fallback → only sensitive check
        if cmd_base in baseline["sensitive"]:
            return {
                "event_type": "SYSTEM_EVENTS",
                "event_name": "TERMINAL_COMMAND_EXECUTED",
                "event_reason": f"Sensitive command '{cmd_base}' executed by {user_id} (default profile)",
                "timestamp": now,
                "severity": "ALERT",
                "command_text": command
            }
        return None

    # Learned baseline
    common = baseline.get("common_commands", {})
    total = baseline.get("total_count", 1)

    # --- 1. Unseen command ---
    if cmd_base not in common:
        return {
            "event_type": "SYSTEM_EVENTS",
            "event_name": "TERMINAL_COMMAND_EXECUTED",
            "event_reason": f"Unseen command '{cmd_base}' executed by {user_id}",
            "timestamp": now,
            "severity": "ALERT",
            "command_text": command
        }

    # --- 2. Frequency ratio ---
    freq_ratio = common[cmd_base] / total

    # (a) Sensitive command handling
    if cmd_base in SENSITIVE_COMMANDS:
        if freq_ratio < 0.05:  # Rare sensitive usage
            return {
                "event_type": "SYSTEM_EVENTS",
                "event_name": "TERMINAL_COMMAND_EXECUTED",
                "event_reason": f"Rare sensitive command '{cmd_base}' executed by {user_id} (<5% frequency)",
                "timestamp": now,
                "severity": "ALERT",
                "command_text": command
            }
        else:
            # Frequent sensitive → treat as normal for this user
            return None

    # (b) Normal command handling
    if freq_ratio < 0.05:  # Rare normal usage
        return {
            "event_type": "SYSTEM_EVENTS",
            "event_name": "TERMINAL_COMMAND_EXECUTED",
            "event_reason": f"Rare command '{cmd_base}' executed by {user_id} (<5% frequency)",
            "timestamp": now,
            "severity": "ALERT",
            "command_text": command
        }

    return None


#cpu stress command for abnormal cpu: stress-ng --cpu 4 --cpu-load 90 --timeout 60s

#stress-ng --temp-path /tmp --vm 2 --vm-bytes 80% --timeout 60s for abnormal memory


def main(stop_event=None):
    print("\033[1;92m!!!!!!!!! SRU Consumer Running (UDP) !!!!!!\033[0m")
    LOG.info("!!!!!!!!! SRU Consumer Running (UDP) !!!!!!")

    while not (stop_event and stop_event.is_set()):
        data, addr = sock.recvfrom(65535)
        metrics = json.loads(data.decode("utf-8"))

        # Only process system-metrics events
        if metrics.get("topic") != "system-metrics":
            continue

        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # ---------- COMMAND EXECUTIONS ----------
        command_executions = metrics.get("command_executions", [])
        if command_executions:
            print(f"Received {len(command_executions)} command executions.")
            LOG.info("[SRU batch] cmds=%s host=%s mac=%s",
                     len(command_executions),
                     metrics.get("hostname"),
                     metrics.get("mac_address"))

            for cmd in command_executions:
                full_cmd = cmd.get("command", "")
                tokens = full_cmd.split()
                cmd_base = tokens[0] if tokens else ""

                print(f"User: {cmd['user_id']}, Time: {cmd['timestamp']}, Command: {full_cmd}")
                LOG.info("[CMD] user=%s base=%s", cmd.get("user_id"), cmd_base)

                cur.execute(
                    """
                    INSERT INTO executed_commands_ueba
                    (timestamp, username, source, command, mac_address, ip_address)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        cmd.get("timestamp"),
                        cmd.get("user_id"),
                        cmd.get("source"),
                        full_cmd,
                        metrics.get("mac_address"),
                        metrics.get("ip_addresses"),
                    )
                )

                baseline = get_command_baseline(cmd.get("user_id"))
                anomaly = detect_command_deviation(cmd.get("user_id"), full_cmd, baseline)
                if anomaly:
                    anomaly.update({
                        "username": cmd.get("user_id"),
                        "timestamp": cmd.get("timestamp"),
                        "log_text": json.dumps(cmd),
                        "command_text": full_cmd,
                        "command_exe_duration": float(cmd.get("duration", 0.0)),
                        "command_repetition": "NO",
                        "event_type": "USER_ACTIVITY_EVENTS",
                        "event_name": "TERMINAL_COMMAND_EXECUTED",
                        "msg_id": "UEBA_SIEM_CMD_EXE_MONI_MSG",
                        "severity": "ALERT"
                    })
                    store_anomaly_to_database_and_siem(anomaly)
                    siem_packet = build_command_exe_moni_packet(anomaly)
                    store_siem_ready_packet(asdict(siem_packet))

                cur.execute("""
                    SELECT COUNT(*) FROM executed_commands_ueba
                    WHERE command = %s AND timestamp > NOW() - INTERVAL '1 minutes'
                """, (full_cmd,))
                repetition_count = cur.fetchone()[0]

                if repetition_count >= 3:
                    LOG.warning("[Repetition] user=%s count=%s cmd=%s",
                                cmd.get("user_id"), repetition_count, full_cmd)
                    anomaly = {
                        "user_id": cmd.get("user_id"),
                        "msg_id": "UEBA_SIEM_CMD_EXE_MONI_MSG",
                        "event_type": "SYSTEM_EVENTS",
                        "event_name": "TERMINAL_COMMAND_EXECUTED",
                        "event_reason": f"Command '{full_cmd}' used {repetition_count} times in last 1 minute by {cmd.get('user_id')}",
                        "timestamp": cmd.get("timestamp"),
                        "log_text": json.dumps(cmd),
                        "severity": "ALERT",
                        "command_text": full_cmd,
                        "command_exe_duration": float(cmd.get("duration", 0.0)),
                        "command_repetition": "YES"
                    }
                    store_anomaly_to_database_and_siem(anomaly)
                    siem_packet = build_command_exe_moni_packet(anomaly)
                    store_siem_ready_packet(asdict(siem_packet))

        # ---------- RESOURCE USAGE (ALWAYS) ----------

        anomalies = detect_anomalous_resource_usage(metrics)

        if anomalies:
            print(f"[INFO] Detected {len(anomalies)} resource anomalies")
            LOG.info("[Resource anomalies] count=%s mac=%s",
                    len(anomalies), metrics.get("mac_address"))

        # Determine top process
        processes = metrics.get("per_process_memory") or []
        if processes:
            top_proc = max(processes, key=lambda p: p.get("rss", 0))
            top_process_pid = top_proc.get("pid")
            top_process_name = top_proc.get("name")
            top_process_rss = top_proc.get("rss")
        else:
            top_process_pid = None
            top_process_name = None
            top_process_rss = None

        # --- Prevent storing empty/null resource usage rows ---
        meaningful_vals = [
            metrics.get("cpu_usage"),
            metrics.get("gpu_usage"),
            metrics.get("ram_usage"),
            metrics.get("memory_usage"),
            metrics.get("disk_read_rate"),
            metrics.get("disk_write_rate"),
            metrics.get("network_bytes_sent"),
            metrics.get("network_bytes_recv"),
            metrics.get("network_packets_sent"),
            metrics.get("network_packets_recv"),
            top_process_pid,
            top_process_name,
            top_process_rss
        ]

        if all(v is None for v in meaningful_vals):
            # LOG.warning("[SKIP] Empty resource_usage row ignored for MAC=%s", metrics.get("mac_address"))
            conn.commit()
            cur.close()
            conn.close()
            continue

        # --- Ensure timestamp is never NULL for resource_usage ---
        ts = metrics.get("timestamp")
        if not ts:
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Insert meaningful resource usage record
        cur.execute(
            """
            INSERT INTO resource_usage_ueba (
                timestamp, username, mac_address, ip_addresses,
                cpu_usage, gpu_usage, ram_usage, memory_usage,
                disk_read_rate, disk_write_rate,
                network_bytes_sent, network_bytes_recv,
                network_packets_sent, network_packets_recv,
                top_process_pid, top_process_name, top_process_rss
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                ts,
                metrics.get("username"),
                metrics.get("mac_address"),
                metrics.get("ip_addresses"),
                metrics.get("cpu_usage"),
                metrics.get("gpu_usage"),
                metrics.get("ram_usage"),
                metrics.get("memory_usage"),
                metrics.get("disk_read_rate"),
                metrics.get("disk_write_rate"),
                metrics.get("network_bytes_sent"),
                metrics.get("network_bytes_recv"),
                metrics.get("network_packets_sent"),
                metrics.get("network_packets_recv"),
                top_process_pid,
                top_process_name,
                top_process_rss
            )
        )

        # for anomaly in anomalies:
        #     metric = anomaly.get("metric")
        #     info = ANOMALY_CATEGORIES.get(metric, {
        #         "Event Type": "Unknown",
        #         "Event Sub Type": "Unknown",
        #         "Event Details": "Unknown anomaly detected"
        #     })

        #     anomaly_msg = {
        #         "msg_id": "UEBA_SIEM_ANOMALOUS_CPU_GPU_RAM_CONSP_MSG",
        #         # "msg_id": "uebaEventQueue",
        #         "event_type": info["Event Type"],
        #         "event_name": info["Event Sub Type"],
        #         "event_reason": info["Event Details"],
        #         "timestamp": metrics.get("timestamp"),
        #         "log_text": json.dumps(metrics),
        #         "severity": "ALERT",
        #         "metric": metric,
        #         "current_value": anomaly.get("current_value")
        #     }

        #     store_anomaly_to_database_and_siem(anomaly_msg)
        #     siem_packet = build_anomalous_cpu_gpu_ram_consp_packet(anomaly_msg)
        #     store_siem_ready_packet(asdict(siem_packet))
        for anomaly in anomalies:
            metric = anomaly.get("metric")
            info = ANOMALY_CATEGORIES.get(metric, {
                "Event Type": "Unknown",
                "Event Sub Type": "Unknown",
                "Event Details": "Unknown anomaly detected"
            })

            anomaly_msg = {
                "msg_id": "UEBA_SIEM_ANOMALOUS_CPU_GPU_RAM_CONSP_MSG",
                "event_type": info["Event Type"],
                "event_name": info["Event Sub Type"],
                "event_reason": info["Event Details"],
                "timestamp": metrics.get("timestamp"),
                # "log_text": json.dumps(metrics),
                "log_text": json.dumps(metrics, default=str),
                "severity": "ALERT",
                "metric": metric,
                "current_value": anomaly.get("current_value")
            }
            anomaly_msg["log_text"] = json.dumps(anomaly_msg, default=str)
            anomaly_msg["user_id"] = metrics.get("username", "unknown")
            anomaly_msg["username"] = metrics.get("username", "unknown")

            # CPU anomaly
            if metric == "cpu_usage":
                anomaly_msg["cpu_anomalous_usage"] = anomaly.get("current_value")
                ts = metrics.get("timestamp")
                anomaly_msg["anomalous_cpu_usage_time"] = datetime.fromisoformat(ts.replace("Z","").replace("z",""))

            # RAM anomaly
            elif metric == "memory_usage":
                anomaly_msg["ram_anomalous_usage"] = anomaly.get("current_value")
                ts = metrics.get("timestamp")
                anomaly_msg["anomalous_ram_usage_time"] = datetime.fromisoformat(ts.replace("Z","").replace("z",""))

            # GPU anomaly
            elif metric == "gpu_usage":
                anomaly_msg["gpu_anomalous_usage"] = anomaly.get("current_value")
                ts = metrics.get("timestamp")
                anomaly_msg["anomalous_gpu_usage_time"] = datetime.fromisoformat(ts.replace("Z","").replace("z",""))


            # Store anomaly into DB
            store_anomaly_to_database_and_siem(anomaly_msg)

            # === NEW: choose correct builder ===
            if metric == "memory_usage":
                siem_packet = build_anomalous_ram_consumption_packet(anomaly_msg)

            elif metric == "gpu_usage":
                siem_packet = build_anomalous_gpu_consumption_packet(anomaly_msg)

            elif metric == "cpu_usage":
                siem_packet = build_anomalous_cpu_consumption_packet(anomaly_msg)

            else:
                siem_packet = build_anomalous_cpu_gpu_ram_consp_packet(anomaly_msg)

            store_siem_ready_packet(asdict(siem_packet))


        # ---------- NETWORK STATUS ----------
        network_records = metrics.get("network_status", [])
        if network_records:
            LOG.info(f"[NetworkStatus] Received {len(network_records)} entries from {metrics.get('hostname')}")

            system_mac = metrics.get("mac_address")  # unified MAC for all interfaces

            for record in network_records:
                iface = record.get("interface", "unknown")
                is_up = record.get("is_up", False)
                speed = record.get("speed_mbps", None)
                mtu = record.get("mtu", None)
                duplex = record.get("duplex", None)
                bytes_sent = record.get("bytes_sent", None)
                bytes_recv = record.get("bytes_recv", None)
                ip = record.get("ip_address", None)
                gateway = record.get("gateway_ip", None)
                ping_ok = record.get("ping_ok", None)
                latency = record.get("latency_ms", None)
                conn_state = record.get("event", "UNKNOWN")

                cur.execute("""
                    SELECT id, is_up, ip_address, connection_status
                    FROM network_status_ueba
                    WHERE mac_address = %s AND interface_name = %s AND snapshot_date = CURRENT_DATE
                    ORDER BY id DESC LIMIT 1
                """, (system_mac, iface))

                existing = cur.fetchone()

                if existing:
                    existing_id, prev_up, prev_ip, prev_conn_state = existing
                    if (prev_up != is_up) or (prev_ip != ip) or (prev_conn_state != conn_state):
                        cur.execute("""
                            UPDATE network_status_ueba
                            SET timestamp = %s,
                                is_up = %s,
                                speed_mbps = %s,
                                mtu = %s,
                                duplex = %s,
                                bytes_sent = %s,
                                bytes_recv = %s,
                                ip_address = %s,
                                gateway_ip = %s,
                                ping_ok = %s,
                                latency_ms = %s,
                                connection_status = %s
                            WHERE id = %s
                        """, (
                            metrics.get("timestamp"),
                            is_up, speed, mtu, duplex,
                            bytes_sent, bytes_recv, ip,
                            gateway, ping_ok, latency, conn_state,
                            existing_id
                        ))
                        LOG.info(f"[NetworkStatus] Updated interface {iface} ({system_mac})")
                else:
                    cur.execute("""
                        INSERT INTO network_status_ueba (
                        timestamp, username, interface_name, is_up, speed_mbps,
                        mtu, duplex, bytes_sent, bytes_recv, ip_address,
                        mac_address, gateway_ip, ping_ok, latency_ms, connection_status, snapshot_date
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_DATE)
                    """, (
                        metrics.get("timestamp"),
                        metrics.get("username"),
                        iface,
                        is_up, speed, mtu, duplex,
                        bytes_sent, bytes_recv, ip,
                        system_mac, gateway, ping_ok, latency, conn_state
                ))

                    LOG.info(f"[NetworkStatus] New interface {iface} recorded ({system_mac})")

        conn.commit()
        cur.close()
        conn.close()



if __name__ == "__main__":
    main()
