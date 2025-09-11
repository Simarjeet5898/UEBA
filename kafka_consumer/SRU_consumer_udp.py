import json
import socket
# from kafka import KafkaConsumer
# from SIEM_connector import create_packet, load_config ,send_json_packet
# from SIEM_connector import create_packet ,send_json_packet
# from store_anomaly import store_anomaly
import os 
# import sys
from datetime import datetime,timedelta
# import mysql.connector
import psycopg2
# from db_send import store_anomaly_to_postgres
from dataclasses import asdict
from helper import store_anomaly_to_database_and_siem
import socket
from helper import build_command_exe_moni_packet, store_siem_ready_packet,build_anomalous_cpu_gpu_ram_consp_packet
# from udp_dispatcher import queues
import logging
LOG = logging.getLogger("SRU Consumer")


from collections import defaultdict

anomaly_last_seen = defaultdict(lambda: datetime.min)
ANOMALY_COOLDOWN = timedelta(minutes=10)


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
SIGMA_THRESHOLD = 2  # 2-sigma rule for anomaly detection

ewma_metrics = {}
ewma_deviation = {}

# Mapping of anomalies to event types and sub-types
ANOMALY_CATEGORIES = {
    "cpu_usage": {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "ANOMALOUS_CPU_CONSUMPTION",
        "Event Details": "Excessive CPU utilization detected",
    },
    "memory_usage": {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "ANOMALOUS_RAM_CONSUMPTION",
        "Event Details": "Unusual memory usage indicating potential attack",
    },
    "disk_usage": {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "DDOS_ATTACK_DETECTED",
        "Event Details": "Unusual increase in disk read/write operations",
    },
    "gpu_usage": {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "ANOMALOUS_GPU_CONSUMPTION",
        "Event Details": "Unexpected GPU usage",
    },
    "system_temperature": {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "DDOS_ATTACK_DETECTED",
        "Event Details": "High system temperature beyond normal thresholds",
    },
    "response_time": {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "DDOS_ATTACK_DETECTED",
        "Event Details": "High Response Time",
    },
    "network_bytes_sent": {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "DDOS_ATTACK_DETECTED",
        "Event Details": "High outbound network traffic",
    },
    "network_bytes_recv": {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "DDOS_ATTACK_DETECTED",
        "Event Details": "Unusual spike in inbound network traffic",
    },
    "network_packets_sent": {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "DDOS_ATTACK_DETECTED",
        "Event Details": "Unusual spike in outbound network traffic",
    },
    "network_packets_recv": {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "DDOS_ATTACK_DETECTED",
        "Event Details": "Sudden surge in incoming network packets",
    },
    "total_files": {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "DDOS_ATTACK_DETECTED",
        "Event Details": "Possible File Overloading",
    },
    "num_gui_processes": {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "DDOS_ATTACK_DETECTED",
        "Event Details": "Possible GUI Overloading",
    },
    "avg_load" : {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "DDOS_ATTACK_DETECTED",
        "Event Details": "Unusual Spike in System Load"
    },
    "num_open_windows" : {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "DDOS_ATTACK_DETECTED",
        "Event Details": "GUI Overloading"
    },
    "total_threads" : {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "PROCESS_CREATION_ACTIVITY",
        "Event Details": "Anomalous thread spawning"
     },
    "total_processes" : {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "PROCESS_CREATION_ACTIVITY",
        "Event Details": "Anomalous Process spawning"
    },
    "disk_read_rate" : {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "DDOS_ATTACK_DETECTED",
        "Event Details": "Unauthorized Disk Reads"
    },
    "disk_write_rate" : {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "DDOS_ATTACK_DETECTED",
        "Event Details": "Unauthorized Disk Writes"
    },
    "encrypted_files" : {
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "LARGE_SCALE_ENCRYPTION",
        "Event Details": "Large Scale Encryption Detected"
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


# One-time table creation & migration before the loop
conn = psycopg2.connect(**DB_CONFIG)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS executed_commands (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP,
    user_id TEXT,
    source TEXT,
    command TEXT
);
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS resource_usage (
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


conn.commit()
cur.close()
conn.close()


def get_command_baseline(user_id, min_samples=20):
    """
    Build a baseline profile of user command usage.
    Falls back to SENSITIVE_COMMANDS if not enough history.
    """
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        cur.execute("""
            SELECT command
            FROM executed_commands
            WHERE user_id = %s
            ORDER BY timestamp DESC
            LIMIT 100;
        """, (user_id,))
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
    now = datetime.utcnow().isoformat()

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

    if cmd_base not in common:
        return {
            "event_type": "SYSTEM_EVENTS",
            "event_name": "TERMINAL_COMMAND_EXECUTED",
            "event_reason": f"Unseen command '{cmd_base}' executed by {user_id}",
            "timestamp": now,
            "severity": "ALERT",
            "command_text": command
        }

    # Optional: frequency deviation check
    freq_ratio = common[cmd_base] / total
    if freq_ratio < 0.05:  # less than 5% of history
        return {
            "event_type": "SYSTEM_EVENTS",
            "event_name": "TERMINAL_COMMAND_EXECUTED",
            "event_reason": f"Rare command '{cmd_base}' executed by {user_id} (<5% frequency)",
            "timestamp": now,
            "severity": "ALERT",
            "command_text": command
        }

    return None


def main(stop_event=None):
    print("\033[1;92m!!!!!!!!! SRU Consumer Running (UDP) !!!!!!\033[0m")
    LOG.info("!!!!!!!!! SRU Consumer Running (UDP) !!!!!!")

    while not (stop_event and stop_event.is_set()):
        data, addr = sock.recvfrom(65535)
        metrics = json.loads(data.decode("utf-8"))

        # Only process system-metrics events
        if metrics.get("topic") != "system-metrics":
            continue

        command_executions = metrics.get("command_executions", [])
        if not command_executions:
            continue

        print(f"Received {len(command_executions)} command executions.")
        LOG.info("[SRU batch] cmds=%s host=%s mac=%s",
                 len(command_executions),
                 metrics.get("hostname"),
                 metrics.get("mac_address"))

        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # ========== COMMAND EXECUTIONS ==========
        # for cmd in command_executions:
        #     full_cmd = cmd.get("command", "")
        #     tokens = full_cmd.split()
        #     cmd_base = tokens[0] if tokens else ""

        #     print(f"User: {cmd['user_id']}, Time: {cmd['timestamp']}, Command: {full_cmd}")
        #     LOG.info("[CMD] user=%s base=%s", cmd.get("user_id"), cmd_base)

        #     # 1. Always save command into executed_commands
        #     cur.execute(
        #         "INSERT INTO executed_commands (timestamp, user_id, source, command) VALUES (%s, %s, %s, %s)",
        #         (
        #             cmd.get("timestamp"),
        #             cmd.get("user_id"),
        #             cmd.get("source"),
        #             full_cmd
        #         )
        #     )

        #     # 2a. Sensitive Command Execution
        #     if cmd_base in SENSITIVE_COMMANDS or any(tok in SENSITIVE_COMMANDS for tok in tokens):
        #         LOG.warning("[Sensitive CMD] user=%s cmd=%s", cmd.get("user_id"), full_cmd)
        #         anomaly = {
        #             "user_id": cmd.get("user_id"),
        #             "msg_id": "UEBA_SIEM_CMD_EXE_MONI_MSG",
        #             "event_type": "SYSTEM_EVENTS",
        #             "event_name": "TERMINAL_COMMAND_EXECUTED",
        #             "event_reason": f"Sensitive command '{full_cmd}' executed by {cmd.get('user_id')}",
        #             "timestamp": cmd.get("timestamp"),
        #             "log_text": json.dumps(cmd),
        #             "severity": "ALERT",
        #             "command_text": full_cmd,
        #             "command_exe_duration": float(cmd.get("duration", 0.0)),
        #             "command_repetition": "NO"
        #         }

        #         store_anomaly_to_database_and_siem(anomaly)
        #         siem_packet = build_command_exe_moni_packet(anomaly)
        #         store_siem_ready_packet(asdict(siem_packet))

        #     # 2b. Repeated Command Execution (>=3 in last 1 minute)
        #     cur.execute("""
        #         SELECT COUNT(*) FROM executed_commands
        #         WHERE command = %s AND timestamp > NOW() - INTERVAL '1 minutes'
        #     """, (full_cmd,))
        #     repetition_count = cur.fetchone()[0]

        #     if repetition_count >= 3:
        #         LOG.warning("[Repetition] user=%s count=%s cmd=%s",
        #                     cmd.get("user_id"), repetition_count, full_cmd)
        #         anomaly = {
        #             "user_id": cmd.get("user_id"),
        #             "msg_id": "UEBA_SIEM_CMD_EXE_MONI_MSG",
        #             "event_type": "SYSTEM_EVENTS",
        #             "event_name": "TERMINAL_COMMAND_EXECUTED",
        #             "event_reason": f"Command '{full_cmd}' used {repetition_count} times in last 1 minute by {cmd.get('user_id')}",
        #             "timestamp": cmd.get("timestamp"),
        #             "log_text": json.dumps(cmd),
        #             "severity": "ALERT",
        #             "command_text": full_cmd,
        #             "command_exe_duration": float(cmd.get("duration", 0.0)),
        #             "command_repetition": "YES"
        #         }

        #         store_anomaly_to_database_and_siem(anomaly)
        #         siem_packet = build_command_exe_moni_packet(anomaly)
        #         store_siem_ready_packet(asdict(siem_packet))
        for cmd in command_executions:
            full_cmd = cmd.get("command", "")
            tokens = full_cmd.split()
            cmd_base = tokens[0] if tokens else ""

            print(f"User: {cmd['user_id']}, Time: {cmd['timestamp']}, Command: {full_cmd}")
            LOG.info("[CMD] user=%s base=%s", cmd.get("user_id"), cmd_base)

            # 1. Always save command into executed_commands
            cur.execute(
                "INSERT INTO executed_commands (timestamp, user_id, source, command) VALUES (%s, %s, %s, %s)",
                (
                    cmd.get("timestamp"),
                    cmd.get("user_id"),
                    cmd.get("source"),
                    full_cmd
                )
            )

            # 2. Fetch baseline for this user
            baseline = get_command_baseline(cmd.get("user_id"))

            # 3. Detect deviation or sensitive command
            anomaly = detect_command_deviation(cmd.get("user_id"), full_cmd, baseline)
            if anomaly:
                # force event_name for consistency
                anomaly["event_name"] = "TERMINAL_COMMAND_EXECUTED"
                anomaly["msg_id"] = "UEBA_SIEM_CMD_EXE_MONI_MSG"
                store_anomaly_to_database_and_siem(anomaly)
                siem_packet = build_command_exe_moni_packet(anomaly)
                store_siem_ready_packet(asdict(siem_packet))

            # 4. Repeated Command Execution (>=3 in last 1 minute)
            cur.execute("""
                SELECT COUNT(*) FROM executed_commands
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


        # ========== RESOURCE ANOMALIES (EWMA) ==========
        anomalies = detect_anomalies(metrics)
        if anomalies:
            print(f"[INFO] Detected {len(anomalies)} resource anomalies")
            LOG.info("[Resource anomalies] count=%s mac=%s",
                     len(anomalies), metrics.get("mac_address"))

            # Extract top process info
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

            # Insert structured resource metrics
            cur.execute(
                """
                INSERT INTO resource_usage (
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
                    metrics.get("timestamp"),
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

            # Send anomalies to pipeline
            for anomaly in anomalies:
                anomaly_msg = {
                    "msg_id": "UEBA_SIEM_ANOMALOUS_CPU_GPU_RAM_CONSP_MSG",
                    "event_type": "SYSTEM_EVENTS",
                    "event_name": "DOS_ATTACK_DETECTED",
                    "event_reason": anomaly.get("Event Details"),
                    "timestamp": metrics.get("timestamp"),
                    "log_text": json.dumps(metrics),
                    "severity": "ALERT",
                }

                store_anomaly_to_database_and_siem(anomaly_msg)
                siem_packet = build_anomalous_cpu_gpu_ram_consp_packet(anomaly_msg)
                store_siem_ready_packet(asdict(siem_packet))

        conn.commit()
        cur.close()
        conn.close()




if __name__ == "__main__":
    main()
