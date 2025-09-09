#!/usr/bin/env python3
import json
import psycopg2
# from kafka import KafkaConsumer
import logging
LOG = logging.getLogger("Process Monitoring Consumer")
from datetime import datetime, timezone
import time
from helper import store_anomaly_to_database_and_siem
import pprint
import socket
# from udp_dispatcher import queues



# ─── Config ───
CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
# UDP_PORT = config["udp"]["server_port"]

# Process consumer internal port
UDP_PORT = 6003

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((UDP_IP, UDP_PORT))


DB_CONFIG = {
    'host': config["local_db"]["host"],
    'user': config["local_db"]["user"],
    'password': config["local_db"]["password"],
    'dbname': config["local_db"]["dbname"]
}


# ─── Ensure process_monitoring table exists ───

def ensure_table(conn):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS process_monitoring (
            id SERIAL PRIMARY KEY,
            event TEXT,
            username TEXT,
            process_name TEXT,
            pid INTEGER,
            ppid INTEGER,
            cmdline TEXT,
            terminal TEXT,
            is_interactive BOOLEAN,
            is_likely_user_process BOOLEAN,
            likely_background_loop BOOLEAN,
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            execution_duration REAL,
            timestamp TIMESTAMP,
            parent_name TEXT
        );
    """)
    conn.commit()
    cur.close()



def detect_suspicious_process(record):
    suspicious_keywords = {"ncat", "nc", "bash -i", "socat", "sh -i", "socket", "reverse_shell"}
    suspicious_paths = ["/tmp", "/dev/shm"]
    anomalies = []

    cmd = ' '.join(record.get("cmdline", [])) if isinstance(record.get("cmdline"), list) else record.get("cmdline", "")
    user = record.get("user", "unknown")
    pname = record.get("process_name", "").lower()
    parent = record.get("parent_name", "").lower()

    # Rule 1: Command line contains suspicious keywords
    if any(kw in cmd for kw in suspicious_keywords):
        anomalies.append({
            "Event Type": "PROCESS_MONITORING",
            "Event Sub Type": "SUSPICIOUS_COMMAND_LINE",
            "Event Details": f"Suspicious command line for user '{user}': {cmd}",
            "metric": "cmdline",
            "Value": cmd
        })

    # Rule 2: Running from suspicious directory
    if any(cmd.startswith(path) for path in suspicious_paths):
        anomalies.append({
            "Event Type": "PROCESS_MONITORING",
            "Event Sub Type": "UNTRUSTED_EXECUTION_PATH",
            "Event Details": f"Command executed from suspicious path: {cmd}",
            "metric": "cmdline",
            "Value": cmd
        })

    # Rule 3: Suspicious parent-child relationship
    if parent in {"python", "python3", "perl", "php"} and pname in {"sh", "bash"}:
        anomalies.append({
            "Event Type": "PROCESS_MONITORING",
            "Event Sub Type": "POTENTIAL_PRIV_ESCALATION",
            "Event Details": f"{parent} spawned {pname} for user '{user}'",
            "metric": "parent_name",
            "Value": f"{parent} -> {pname}"
        })

    return anomalies


def insert_process_record(conn, record, metrics):

    cur = conn.cursor()

    insert_sql = """
        INSERT INTO process_monitoring (
            event, username, process_name, pid, ppid, cmdline, terminal,
            is_interactive, is_likely_user_process, likely_background_loop,
            start_time, end_time, execution_duration, timestamp, parent_name
        ) VALUES (
            %(event)s, %(user)s, %(process_name)s, %(pid)s, %(ppid)s, %(cmdline)s, %(terminal)s,
            %(is_interactive)s, %(is_likely_user_process)s, %(likely_background_loop)s,
            %(start_time)s, %(end_time)s, %(execution_duration)s, %(timestamp)s, %(parent_name)s
        );
    """

    # Ensure optional fields have defaults
    for field in ["end_time", "execution_duration"]:
        record.setdefault(field, None)

    try:
        cur.execute(insert_sql, {
            "event": record.get("event"),
            "user": record.get("user"),
            "process_name": record.get("process_name"),
            "pid": record.get("pid"),
            "ppid": record.get("ppid"),
            "cmdline": ' '.join(record.get("cmdline", [])) if isinstance(record.get("cmdline"), list) else record.get("cmdline"),
            "terminal": record.get("terminal"),
            "is_interactive": record.get("is_interactive"),
            "is_likely_user_process": record.get("is_likely_user_process"),
            "likely_background_loop": record.get("likely_background_loop"),
            "start_time": record.get("start_time"),
            "end_time": record.get("end_time"),
            "execution_duration": record.get("execution_duration"),
            "timestamp": record.get("timestamp"),
            "parent_name": record.get("parent_name")
        })
        conn.commit()
    except Exception as e:
        LOG.error(f"[ERROR] Failed to insert process record: {e}\nData: {json.dumps(record, indent=2)}")
        conn.rollback()
    finally:
        cur.close()

    # ─── Suspicious process detection ───
    suspicious_anomalies = detect_suspicious_process(record)
    if suspicious_anomalies:
        for anomaly in suspicious_anomalies:
            anomaly["Event Type"] = "PROCESS_MONITORING"
            anomaly["Event Sub Type"] = "PROCESS_STARTED"
            alert_data = {
                "user_id": record.get("user") or metrics.get("username", "unknown"),
                # "timestamp": anomaly.get("timestamp"),
                # "timestamp": anomaly.get("timestamp").isoformat() if isinstance(anomaly.get("timestamp"), datetime) else str(anomaly.get("timestamp")),
                "timestamp": (anomaly.get("timestamp") or datetime.now(timezone.utc)).isoformat(),
                "Event Type": anomaly["Event Type"],
                "Event Sub Type": anomaly["Event Sub Type"],
                # "event_type": anomaly.get("Event Type", "PROCESS_MONITORING"),
                # "event_subtype": anomaly.get("Event Sub Type", "PROCESS_STARTED"),
                "severity": "Medium",
                "attacker_info": "N/A",
                "component": "Process Monitoring",
                "resource": record.get("process_name") or "unknown",
                "event_reason": anomaly.get("Event Details", ""),
                "device_ip": next(iter(metrics.get("ip_addresses", [])), "127.0.0.1"),
                "device_mac": metrics.get("mac_address", "unknown"),
                "log_text": anomaly.get("Event Details", ""),
                "risk_score": 5,  # or calculate based on logic
                "anomalies": [anomaly],
                "metrics": {
                    "cmdline": record.get("cmdline"),
                    "pid": record.get("pid"),
                    "ppid": record.get("ppid"),
                    "parent_name": record.get("parent_name"),
                    "process_name": record.get("process_name")
                }
                
            }
            # print("\n[DEBUG] Sending Anomaly Alert to SIEM:")
            pprint.pprint(alert_data)
            try:
                store_anomaly_to_database_and_siem(json.dumps(alert_data))  
            except Exception as e:
                LOG.error(f"[ERROR] Failed to log/send anomaly: {e}")



# ─── Main consumer logic ───
# def main():
def main(stop_event=None):
    conn = psycopg2.connect(**DB_CONFIG)
    ensure_table(conn)
    print("\033[1;92m!!!!!!!!! Process Creation and Execution Monitoring Consumer running (UDP) !!!!!!\033[0m")
    LOG.info("!!!!!!!!! Process Creation and Execution Monitoring Consumer running (UDP) !!!!!!")


    # while True:
    while not (stop_event and stop_event.is_set()):
        data, addr = sock.recvfrom(65535)
        metrics = json.loads(data.decode("utf-8"))
        # metrics = queues["process"].get()
        # print(f"[DEBUG] Process Monitoring Consumer received raw event: {metrics.get('topic')} | Keys: {list(metrics.keys())}")


        # Only process system-metrics events
        if metrics.get("topic") != "system-metrics":
            continue

        events = metrics.get("process_events", [])
        if not events:
            continue

        for record in events:
            LOG.info("[Process batch] count=%s host=%s user=%s",
                len(events), metrics.get("hostname"), metrics.get("username"))
            print("[PROCESS EVENT RECEIVED]:", json.dumps(record, indent=2))
            for ts_field in ("start_time", "end_time", "timestamp"):
                if isinstance(record.get(ts_field), str):
                    try:
                        record[ts_field] = datetime.fromisoformat(record[ts_field])
                    except Exception:
                        pass  # keep as string if parsing fails

            insert_process_record(conn, record, metrics)

if __name__ == "__main__":
    main()
