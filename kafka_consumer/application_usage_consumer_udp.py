
"""
Application Usage Monitoring Consumer

This script listens to the Kafka topic 'system-metrics' to consume application usage
events emitted by a producer function (e.g., `track_application_usage()`) running on
endpoint machines. It logs each application launch and exit event into a PostgreSQL
database, supporting later analysis for UEBA_11 (Application Usage Monitoring).

Kafka Topic:
    - system-metrics

Database Table:
    - application_usage

Schema:
    - username, process_name, pid, ppid, cmdline, terminal, status
    - cpu_percent, memory_percent, start_time, end_time, duration_secs, timestamp

 What Gets Logged:
    - User-launched desktop and terminal applications
    - Apps installed via Snap, AppImage, Flatpak, or located in:
        • /snap/
        • /opt/
        • /usr/bin/
    - Applications whose executables match a known list (`INSTALLED_EXEC_NAMES`)
    - Long-running apps with measurable CPU/memory usage (above 0.5%)

 What Is Filtered Out:
    - System/background processes (e.g., cron, systemd, sshd, dbus)
    - Known subprocesses or helper processes of browsers/editors, e.g.:
        • crashpad_handler
        • tsserver.js
        • WebExtensions
        • Socket Process
    - Transient or short-lived apps that exit before the polling interval
    - Kernel-space tasks and processes with missing usernames
    - Non-user apps whose executables don’t match heuristics or known paths

How It Works:
    - The producer scans active processes at regular intervals (default: 5s)
    - Application `launch` events are logged when new matching processes appear
    - Application `exit` events are detected when processes disappear
    - Duration is calculated based on first and last seen timestamps
    - CPU and memory metrics are tracked to determine active/inactive state

Limitations:
    - Frequency analysis and anomaly detection are not performed here (can be added externally)
    - Detection accuracy depends on polling frequency and process visibility
    - Some short-lived apps may not be captured if they terminate too quickly

Preconditions:
    - Kafka producer agent must be installed and running on endpoint
    - PostgreSQL server must be accessible with correct schema
    - System-metrics topic must be active and receiving application usage data

Author: [Your Name or Team]
Date: [Insert Date]
"""

import json
import psycopg2
# from kafka import KafkaConsumer
import socket
import logging
from datetime import datetime
# import uuid 
from helper import store_anomaly_to_database_and_siem, build_anomalous_application_usage_packet, store_siem_ready_packet
# from udp_dispatcher import queues
from dataclasses import asdict
import threading
import time



CONFIG_PATH = "/home/config.json"
# CONFIG_PATH = "/home/simar/Documents/UEBA_BACKEND/config/config.json"
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

# UDP_IP = config["udp"]["server_ip"]
# UDP_PORT = config["udp"]["server_port"]
UDP_IP = config["udp"]["server_ip"]

# Application consumer internal port
UDP_PORT = 6001  

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((UDP_IP, UDP_PORT))


DB_CONFIG = {
    'host': config["local_db"]["host"],
    'user': config["local_db"]["user"],
    'password': config["local_db"]["password"],
    'dbname': config["local_db"]["dbname"]
}

ANOMALY_CONFIG = config.get("application_usage_anomaly", {})



# ─── Ensure application_usage table exists ───

def ensure_table(conn):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS application_usage (
            id SERIAL PRIMARY KEY,
            username TEXT,
            process_name TEXT,
            pid INTEGER,
            ppid INTEGER,
            parent_name TEXT,
            cmdline TEXT,
            status TEXT,
            cpu_percent REAL,
            memory_percent REAL,
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            duration_secs REAL,
            timestamp TIMESTAMP,
            ip_address TEXT,
            mac_address TEXT,
            network_activity BOOLEAN DEFAULT FALSE
        );
    """)
    conn.commit()
    cur.close()


############


# def create_latency_monitoring_table(conn):
#     cur = conn.cursor()
#     cur.execute("""
#         CREATE TABLE IF NOT EXISTS latency_monitoring (
#             id SERIAL PRIMARY KEY,
#             username TEXT,
#             cpu_percent REAL,
#             memory_percent REAL,
#             startup_latency REAL,
#             response_time REAL,
#             io_wait_time REAL,
#             disk_read_rate REAL,
#             disk_write_rate REAL,
#             load_average REAL,
#             network_bytes_sent BIGINT,
#             network_bytes_recv BIGINT,
#             context_switches BIGINT,
#             system_temperature REAL,
#             timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
#         );
#     """)
#     conn.commit()
#     cur.close()

def hourly_latency_aggregator(conn):
    while True:
        time.sleep(3600)

        cur = conn.cursor()

        cur.execute("""
            INSERT INTO latency_monitoring (
                kernel_worst_latency_ms,
                kernel_avg_latency_ms,
                sched_avg_delay_ms,
                rt_min_latency_us,
                rt_avg_latency_us,
                rt_max_latency_us,
                username,
                cpu_percent,
                memory_percent,
                startup_latency,
                response_time,
                io_wait_time,
                disk_read_rate,
                disk_write_rate,
                load_average,
                network_bytes_sent,
                network_bytes_recv,
                context_switches,
                system_temperature,
                timestamp,
                aggregation_type
            )
            SELECT 
                MAX(kernel_worst_latency_ms),
                AVG(kernel_avg_latency_ms),
                NULL,
                AVG(sched_avg_delay_ms),
                MAX(sched_max_delay_ms),
                SUM(sched_sample_count),
                MIN(rt_min_latency_us),
                AVG(rt_avg_latency_us),
                MAX(rt_max_latency_us),
                username,
                AVG(cpu_percent),
                AVG(memory_percent),
                AVG(startup_latency),
                AVG(response_time),
                AVG(io_wait_time),
                AVG(disk_read_rate),
                AVG(disk_write_rate),
                AVG(load_average),
                AVG(network_bytes_sent),
                AVG(network_bytes_recv),
                AVG(context_switches),
                AVG(system_temperature),
                NOW(),
                'hourly'
            FROM latency_monitoring
            WHERE aggregation_type = 'realtime'
              AND timestamp > NOW() - INTERVAL '1 hour'
            GROUP BY username;
        """)

        conn.commit()
        cur.close()


def create_latency_monitoring_table(conn):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS latency_monitoring (
            id SERIAL PRIMARY KEY,

            -- NEW UEBA_015 latency fields (FIRST)
            kernel_worst_latency_ms REAL,
            kernel_avg_latency_ms REAL,

            sched_avg_delay_ms REAL,

            rt_min_latency_us REAL,
            rt_avg_latency_us REAL,
            rt_max_latency_us REAL,

            -- OLD FIELDS (keep them)
            username TEXT,
            cpu_percent REAL,
            memory_percent REAL,
            startup_latency REAL,
            response_time REAL,
            io_wait_time REAL,
            disk_read_rate REAL,
            disk_write_rate REAL,
            load_average REAL,
            network_bytes_sent BIGINT,
            network_bytes_recv BIGINT,
            context_switches BIGINT,
            system_temperature REAL,

            -- NEW (IMPORTANT)
            aggregation_type TEXT DEFAULT 'realtime',

            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    cur.close()



def insert_usage_record(conn, record):
    cur = conn.cursor()

    # Ensure optional fields are set to None if missing
    for key in ["end_time", "duration_secs", "parent_name", "cmdline",
                "ip_address", "mac_address", "network_activity"]:
        record.setdefault(key, None)

    try:
        event = record.get("event")

        if event == "launch":
            # Always insert new row on launch
            insert_sql = """
                INSERT INTO application_usage (
                    username, process_name, pid, ppid,
                    parent_name, cmdline, status,
                    cpu_percent, memory_percent,
                    start_time, end_time, duration_secs,
                    timestamp, ip_address, mac_address, network_activity
                ) VALUES (
                    %(username)s, %(process_name)s, %(pid)s, %(ppid)s,
                    %(parent_name)s, %(cmdline)s, %(status)s,
                    %(cpu_percent)s, %(memory_percent)s,
                    %(start_time)s, %(end_time)s, %(duration_secs)s,
                    %(timestamp)s, %(ip_address)s, %(mac_address)s, %(network_activity)s
                );
            """
            cur.execute(insert_sql, record)


        elif event == "exit":
            # Finalize row when process exits
            update_sql = """
                UPDATE application_usage
                SET end_time     = %(end_time)s,
                    duration_secs = %(duration_secs)s,
                    status        = 'inactive',
                    timestamp     = %(timestamp)s,
                    network_activity = %(network_activity)s
                WHERE pid = %(pid)s AND start_time = %(start_time)s;
            """
            cur.execute(update_sql, record)

            # Fallback if no launch row was ever inserted
            if cur.rowcount == 0:
                insert_sql = """
                    INSERT INTO application_usage (
                        username, process_name, pid, ppid,
                        parent_name, cmdline, status,
                        cpu_percent, memory_percent,
                        start_time, end_time, duration_secs,
                        timestamp, ip_address, mac_address, network_activity
                    ) VALUES (
                        %(username)s, %(process_name)s, %(pid)s, %(ppid)s,
                        %(parent_name)s, %(cmdline)s, %(status)s,
                        %(cpu_percent)s, %(memory_percent)s,
                        %(start_time)s, %(end_time)s, %(duration_secs)s,
                        %(timestamp)s, %(ip_address)s, %(mac_address)s, %(network_activity)s
                    );
                """
                cur.execute(insert_sql, record)

        conn.commit()

    except Exception as e:
        logging.error(f"Failed to insert/update record: {e}\nData: {record}")
        conn.rollback()
    finally:
        cur.close()

# def detect_anomalous_application_usage(record, state_cache=None):
#     if state_cache is None:
#         state_cache = {}

#     anomalies = []
#     proc = record.get("process_name", "").lower()

#     # 1. Sensitive applications
#     sensitive_apps = {"nmap", "hydra", "sqlmap", "john", "airmon-ng"}
#     if proc in sensitive_apps:
#         anomalies.append(f"Sensitive application detected: {proc}")

#     # 2. High CPU / Memory usage
#     cpu = record.get("cpu_percent", 0) or 0
#     mem = record.get("memory_percent", 0) or 0
#     if cpu > 20:
#         anomalies.append(f"High CPU usage detected ({cpu}%) by {proc}")
#     if mem > 20:
#         anomalies.append(f"High memory usage detected ({mem}%) by {proc}")

#     # 3. Suspicious command line
#     cmdline = record.get("cmdline", "") or ""
#     cmdline_lower = cmdline.lower()
#     suspicious_tokens = ["powershell", "wget", "curl", "nc ", "ncat", "base64", "sh -c"]
#     if any(tok in cmdline_lower for tok in suspicious_tokens):
#         anomalies.append(f"Suspicious command line for {proc}: {cmdline}")

#     # 4. Unusual parent process
#     parent = (record.get("parent_name") or "").lower()
#     ALLOWED_PARENTS = {
#         "bash", "zsh", "gnome-shell", "explorer.exe", "init",
#         "systemd", "brave-browser", "firefox", "chrome", "code","oosplash",         
#         "soffice.bin"  
#     }
#     if parent and parent not in ALLOWED_PARENTS:
#         anomalies.append(f"Unusual parent process: {parent} launched {proc}")

#     # 5. Unexpected network activity
#     if record.get("network_activity") and proc not in ("firefox", "brave", "chrome", "edge"):
#         anomalies.append(f"Unexpected network activity by {proc}")

#     # 6. Odd-hour execution (before 5AM or after 7PM)
#     try:
#         ts = record.get("timestamp")
#         ts = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
#         if ts and (ts.hour < 5 or ts.hour > 19):
#             anomalies.append(f"Unusual execution time: {ts.hour}:00 for {proc}")
#     except Exception:
#         pass

#     # 7. Frequency-based anomalies (more than 3 launches/min)
#     now = datetime.now()
#     history = state_cache.setdefault(proc, [])
#     history.append(now)

#     # retain only last 60 seconds
#     state_cache[proc] = [t for t in history if (now - t).seconds < 60]

#     if len(state_cache[proc]) > 3:
#         anomalies.append(f"Frequent launches of {proc} detected ({len(state_cache[proc])}/min)")

#     return anomalies or None

def detect_anomalous_application_usage(record, state_cache):
    anomalies = []

    proc = (record.get("process_name") or "").lower()
    parent = (record.get("parent_name") or "").lower()
    cmdline = (record.get("cmdline") or "").lower()

    # Load config values
    freq_window = ANOMALY_CONFIG.get("frequency_window_sec", 60)
    freq_threshold = ANOMALY_CONFIG.get("frequency_threshold", 3)

    high_cpu_thr = ANOMALY_CONFIG.get("high_cpu_threshold", 20)
    high_mem_thr = ANOMALY_CONFIG.get("high_memory_threshold", 20)

    odd_hour_start = ANOMALY_CONFIG.get("odd_hour_start", 19)
    odd_hour_end   = ANOMALY_CONFIG.get("odd_hour_end", 5)

    sensitive_apps = set(ANOMALY_CONFIG.get("sensitive_apps", []))
    suspicious_tokens = ANOMALY_CONFIG.get("suspicious_tokens", [])
    allowed_parents  = set(ANOMALY_CONFIG.get("allowed_parents", []))

    # 1. Sensitive apps
    if proc in sensitive_apps:
        anomalies.append(f"Sensitive application detected: {proc}")

    # 2. High CPU / Memory
    cpu = record.get("cpu_percent") or 0
    mem = record.get("memory_percent") or 0

    if cpu > high_cpu_thr:
        anomalies.append(f"High CPU usage detected ({cpu}%) by {proc}")

    if mem > high_mem_thr:
        anomalies.append(f"High memory usage detected ({mem}%) by {proc}")

    # 3. Suspicious command line
    if any(tok in cmdline for tok in suspicious_tokens):
        anomalies.append(f"Suspicious command line for {proc}: {cmdline}")

    # 4. Unusual parent process
    if parent and parent not in allowed_parents:
        anomalies.append(f"Unusual parent process: {parent} launched {proc}")

    # 5. Unexpected network activity
    if record.get("network_activity") and proc not in ("firefox", "brave", "chrome", "edge"):
        anomalies.append(f"Unexpected network activity by {proc}")

    # 6. Odd-hour execution
    ts = record.get("timestamp")
    try:
        ts = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
    except:
        ts = None

    if ts:
        if ts.hour > odd_hour_start or ts.hour < odd_hour_end:
            anomalies.append(f"Unusual execution time: {ts.hour}:00 for {proc}")

    # 7. Frequency-based anomaly (config-driven)
    if record.get("event") == "launch":
        now = datetime.now()
        history = state_cache.setdefault(proc, [])
        history.append(now)

        # keep only recent events in window
        state_cache[proc] = [t for t in history if (now - t).seconds < freq_window]

        if len(state_cache[proc]) > freq_threshold:
            anomalies.append(
                f"Frequent launches of {proc} detected ({len(state_cache[proc])}/{freq_window}s)"
            )
    return anomalies or None


def insert_latency_record(conn, record):
    cur = conn.cursor()

    insert_sql = """
        INSERT INTO latency_monitoring (
            kernel_worst_latency_ms,
            kernel_avg_latency_ms,
            sched_avg_delay_ms,
            rt_min_latency_us,
            rt_avg_latency_us,
            rt_max_latency_us,
            username,
            cpu_percent,
            memory_percent,
            startup_latency,
            response_time,
            io_wait_time,
            disk_read_rate,
            disk_write_rate,
            load_average,
            network_bytes_sent,
            network_bytes_recv,
            context_switches,
            system_temperature,
            timestamp,
            aggregation_type       -- ADD THIS
        ) VALUES (
            %(kernel_worst_latency_ms)s,
            %(kernel_avg_latency_ms)s,
            %(sched_avg_delay_ms)s,
            %(rt_min_latency_us)s,
            %(rt_avg_latency_us)s,
            %(rt_max_latency_us)s,
            %(username)s,
            %(cpu_percent)s,
            %(memory_percent)s,
            %(startup_latency)s,
            %(response_time)s,
            %(io_wait_time)s,
            %(disk_read_rate)s,
            %(disk_write_rate)s,
            %(load_average)s,
            %(network_bytes_sent)s,
            %(network_bytes_recv)s,
            %(context_switches)s,
            %(system_temperature)s,
            %(timestamp)s,
            %(aggregation_type)s     -- ADD THIS
        );
    """


    cur.execute(insert_sql, record)
    conn.commit()
    cur.close()

STATE_CACHE = {}


def main(stop_event=None):
    conn = psycopg2.connect(**DB_CONFIG)
    ensure_table(conn)  # Ensure the application usage table exists
    create_latency_monitoring_table(conn)  # Ensure the latency monitoring table exists
    print("\033[1;92m!!!!!!!!! Application usage Consumer running (UDP) !!!!!!\033[0m")

    threading.Thread(
        target=hourly_latency_aggregator,
        args=(conn,),
        daemon=True
    ).start()
    
    # Helper: normalize datetimes before JSON
    def normalize_record(rec):
        return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in rec.items()}

    while not (stop_event and stop_event.is_set()):
        data, addr = sock.recvfrom(65535)
        metrics = json.loads(data.decode("utf-8"))

        # Only process system-metrics events
        if metrics.get("topic") != "system-metrics":
            continue

        usage_list = metrics.get("application_usage", [])

        # Insert application usage records
        if usage_list:
            for record in usage_list:
                print("[Application usage received]:", json.dumps(normalize_record(record), indent=2))

                # Convert timestamps if necessary
                for ts_field in ("start_time", "end_time", "timestamp"):
                    if isinstance(record.get(ts_field), str):
                        try:
                            record[ts_field] = datetime.fromisoformat(record[ts_field])
                        except Exception:
                            pass  # ignore invalid timestamp format

                # Insert into application_usage only on launch/exit
                event_type = record.get("event")
                if event_type in ("launch", "exit"):
                    insert_usage_record(conn, record)

                # Check anomalous application usage
                # anomalies = detect_anomalous_application_usage(record)
                anomalies = detect_anomalous_application_usage(record, STATE_CACHE)
                if anomalies:
                    for reason in anomalies:
                        # Normalize timestamp for anomaly
                        ts = record.get("timestamp")
                        if isinstance(ts, datetime):
                            ts = ts.isoformat()
                        elif not ts:
                            ts = datetime.now().isoformat()

                        anomaly = {
                            "msg_id": "UEBA_SIEM_ANOMALOUS_APPLICATION_USAGE_MSG",
                            "event_type": "USER_ACTIVITY_EVENTS",  
                            "event_name": "ANOMALOUS_APPLICATION_USAGE", # ADDED IN CONFIG
                            "event_reason": reason,
                            "timestamp": ts,
                            "log_text": json.dumps(normalize_record(record)),
                            "severity": "ALERT",
                            "username": record.get("username"),
                            "process_name": record.get("process_name"),
                            "pid": record.get("pid"),
                            "ppid": record.get("ppid"),
                            # "cmdline": record.get("cmdline"),
                            "anomalous_application_name": record.get("process_name"),
                            "tty": record.get("terminal"),
                            "cpu_time": record.get("duration_secs"),
                        }

                        # Store anomaly in DB + send to SIEM
                        try:
                            store_anomaly_to_database_and_siem(anomaly)
                            siem_packet = build_anomalous_application_usage_packet(anomaly)
                            store_siem_ready_packet(asdict(siem_packet))
                        except Exception as e:
                            logging.error(f"Error during database/siem operation: {e}")

        # Insert latency data from the same producer message
        # latency_record = {
        #     "username":           metrics.get("username"),
        #     "cpu_percent":        metrics.get("cpu_usage"),
        #     "memory_percent":     metrics.get("memory_usage"),
        #     "startup_latency":    metrics.get("startup_latency"),
        #     "response_time":      metrics.get("response_time"),
        #     "io_wait_time":       metrics.get("io_wait_time"),
        #     "disk_read_rate":     metrics.get("disk_read_rate"),
        #     "disk_write_rate":    metrics.get("disk_write_rate"),
        #     "load_average":       metrics.get("avg_load"),
        #     "network_bytes_sent": metrics.get("network_bytes_sent"),
        #     "network_bytes_recv": metrics.get("network_bytes_recv"),
        #     "context_switches":   metrics.get("context_switches"),
        #     "system_temperature": metrics.get("system_temperature"),
        #     "timestamp":          metrics.get("timestamp") if metrics.get("timestamp") else datetime.now().isoformat()
        # }
        latency_record = {
            "kernel_worst_latency_ms": metrics["kernel_latency"].get("worst_latency_ms"),
            "kernel_avg_latency_ms":   metrics["kernel_latency"].get("average_latency_ms"),
            # "kernel_top_event":        metrics["kernel_latency"].get("top_event"),

            "sched_avg_delay_ms":  metrics["scheduling_latency"].get("avg_delay_ms"),
            # "sched_max_delay_ms":  metrics["scheduling_latency"].get("max_delay_ms"),
            # "sched_sample_count":  metrics["scheduling_latency"].get("sample_count"),

            "rt_min_latency_us":  metrics["realtime_latency"].get("min_latency_us"),
            "rt_avg_latency_us":  metrics["realtime_latency"].get("avg_latency_us"),
            "rt_max_latency_us":  metrics["realtime_latency"].get("max_latency_us"),

            "username":           metrics.get("username"),
            "cpu_percent":        metrics.get("cpu_usage"),
            "memory_percent":     metrics.get("memory_usage"),
            "startup_latency":    metrics.get("startup_latency"),
            "response_time":      metrics.get("response_time"),
            "io_wait_time":       metrics.get("io_wait_time"),
            "disk_read_rate":     metrics.get("disk_read_rate"),
            "disk_write_rate":    metrics.get("disk_write_rate"),
            "load_average":       metrics.get("avg_load"),
            "network_bytes_sent": metrics.get("network_bytes_sent"),
            "network_bytes_recv": metrics.get("network_bytes_recv"),
            "context_switches":   metrics.get("context_switches"),
            "system_temperature": metrics.get("system_temperature"),
            "timestamp":          metrics.get("timestamp") or datetime.now().isoformat()
            
        }
        latency_record["aggregation_type"] = "realtime"

        insert_latency_record(conn, latency_record)




if __name__ == "__main__":
    main()
