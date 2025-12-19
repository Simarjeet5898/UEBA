import json
import logging
import psycopg2
import socket
from datetime import datetime

LOG = logging.getLogger("Heartbeat Consumer")

# === Config Load ===
CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
UDP_PORT = 6008   # 

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((UDP_IP, UDP_PORT))

DB_CONFIG = {
    'host': config["local_db"]["host"],
    'user': config["local_db"]["user"],
    'password': config["local_db"]["password"],
    'dbname': config["local_db"]["dbname"]
}


def init_db():
    """Create all required tables at service startup."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # ---- Table 1: client_status_ueba ----
        cur.execute("""
            CREATE TABLE IF NOT EXISTS client_status_ueba (
                id SERIAL PRIMARY KEY,
                client_id TEXT UNIQUE,
                last_seen TIMESTAMP,
                status TEXT
            );
        """)

        # ---- Table 2: system_status_ueba ----
        cur.execute("""
            CREATE TABLE IF NOT EXISTS system_status_ueba (
                id SERIAL PRIMARY KEY,
                client_id TEXT,
                event TEXT,
                event_type TEXT,
                status TEXT NULL,
                details TEXT NULL,
                timestamp TIMESTAMP,
                boot_time TIMESTAMP NULL,
                close_time TIMESTAMP NULL,
                UNIQUE (client_id, event, event_type, details)
            );
        """)

        conn.commit()
        cur.close()
        conn.close()
        # print("[DB INIT] Tables client_status_ueba & system_status_ueba ensured.")

    except Exception as e:
        print(f"[DB INIT ERROR] {e}")
        LOG.error(f"[DB INIT ERROR] {e}")



def store_heartbeat(event):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # 1. Create table if not exists
        cur.execute("""
            CREATE TABLE IF NOT EXISTS client_status_ueba (
                id SERIAL PRIMARY KEY,
                client_id TEXT UNIQUE,
                last_seen TIMESTAMP,
                status TEXT
            );
        """)

        client_id = event.get("client_id", "unknown")
        timestamp_str = event.get("timestamp")
        last_seen = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        status = event.get("status", "active")   # take from producer

        # 2. Upsert client status
        cur.execute("""
            INSERT INTO client_status_ueba (client_id, last_seen, status)
            VALUES (%s, %s, %s)
            ON CONFLICT (client_id) DO UPDATE
            SET last_seen = EXCLUDED.last_seen,
                status = EXCLUDED.status;   -- respect producer status
        """, (client_id, last_seen, status))

        # 3. Mark old clients inactive (> 2 min, only if still active)
        cur.execute("""
            UPDATE client_status_ueba
            SET status = 'inactive'
            WHERE status='active'
              AND last_seen < (NOW() - INTERVAL '10 seconds');
        """)

        # 4. Count active clients
        cur.execute("SELECT COUNT(*) FROM client_status_ueba WHERE status='active';")
        active_count = cur.fetchone()[0]

        conn.commit()
        cur.close()
        conn.close()

        LOG.info(f"Heartbeat stored for client {client_id} at {last_seen} (status={status})")
        print(f"[Heartbeat Consumer] Total active clients = {active_count}")

    except Exception as e:
        LOG.error(f"Client status insert error: {e}")


def store_system_status(event):
    """Store or update system, subsystem, config, and logging facility change events."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # === Ensure table exists ===
        cur.execute("""
            CREATE TABLE IF NOT EXISTS system_status_ueba (
                id SERIAL PRIMARY KEY,
                client_id TEXT,
                event TEXT,                 -- clean event/service/config/log name
                event_type TEXT,            -- 'system', 'subsystem', 'config_change', or 'logging'
                status TEXT NULL,           -- active/inactive (for subsystems)
                details TEXT NULL,          -- extra info for logging actions
                timestamp TIMESTAMP,
                boot_time TIMESTAMP NULL,   -- only for startup
                close_time TIMESTAMP NULL,  -- only for shutdown/reboot/abort
                UNIQUE (client_id, event, event_type, details)
            );
        """)

        # --- Extract core fields ---
        client_id = event.get("client_id", "unknown")
        raw_event = event.get("event", "unknown")
        timestamp_str = event.get("timestamp")
        ts = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

        event_type = "unknown"
        event_name = raw_event
        status = None
        details = None
        boot_time = None
        close_time = None

        # === SYSTEM EVENTS ===
        if raw_event.startswith("system_"):
            event_type = "system"
            event_name = raw_event.replace("system_", "")

            if event_name == "startup":
                boot_time = ts
            elif event_name in ("shutdown", "abort", "reboot"):
                close_time = ts

        # === SUBSYSTEM EVENTS ===
        elif raw_event.startswith("subsystem_"):
            event_type = "subsystem"
            event_name = raw_event.replace("subsystem_", "")

            if event_name.startswith("init_"):
                core = event_name.replace("init_", "")
                if core.endswith("_active"):
                    status = "active"
                    event_name = core.replace("_active", "")
                elif core.endswith("_inactive"):
                    status = "inactive"
                    event_name = core.replace("_inactive", "")
                else:
                    event_name = core
            elif event_name.startswith("startup_"):
                status = "active"
                event_name = event_name.replace("startup_", "")
            elif event_name.startswith("shutdown_"):
                status = "inactive"
                event_name = event_name.replace("shutdown_", "")
            else:
                status = "unknown"

        # === CONFIG CHANGE EVENTS ===
        elif raw_event.startswith("config_change_"):
            event_type = "config_change"
            event_name = raw_event.replace("config_change_", "")

        # === LOGGING EVENTS ===
        elif raw_event.startswith("logging_"):
            event_type = "logging"
            event_name = raw_event.replace("logging_", "")

            # Split like: "file_rename_test.log" → action="file_rename", details="test.log"
            parts = event_name.split("_", 2)
            if len(parts) >= 2:
                event_name = f"{parts[0]}_{parts[1]}"
                if len(parts) == 3:
                    details = parts[2]
            else:
                details = None

        # === UNKNOWN EVENTS ===
        else:
            event_type = "unknown"
            event_name = raw_event

        # === UPSERT ===
        cur.execute("""
            INSERT INTO system_status_ueba (client_id, event, event_type, status, details, timestamp, boot_time, close_time)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (client_id, event, event_type, details)
            DO UPDATE SET
                timestamp = EXCLUDED.timestamp,
                status = COALESCE(EXCLUDED.status, system_status_ueba.status),
                boot_time = COALESCE(EXCLUDED.boot_time, system_status_ueba.boot_time),
                close_time = COALESCE(EXCLUDED.close_time, system_status_ueba.close_time);

        """, (client_id, event_name, event_type, status, details, ts, boot_time, close_time))

        conn.commit()
        cur.close()
        conn.close()

        print(f"[SystemStatus Consumer] {event_type.upper()} → {event_name} ({status}) details={details} client={client_id}")

    except Exception as e:
        LOG.error(f"System status insert/update error: {e}")


def main(stop_event=None):
    print("\033[1;32m  !!!!!!!!!!!Heartbeat & System Status Consumer started (UDP)!!!!!!!!!!!!!!\033[0m")

    LOG.info("Heartbeat consumer started (UDP)")
    init_db()

    try:
        while not (stop_event and stop_event.is_set()):
            data, addr = sock.recvfrom(65535)
            try:
                event = json.loads(data.decode("utf-8"))
            except json.JSONDecodeError:
                print(f"[DEBUG] Invalid JSON received from {addr}")
                continue

            event_type = event.get("type", "unknown")
            event_name = event.get("event", "unknown")

            # --- Handle Heartbeat messages ---
            if event_type == "heartbeat":
                print(f"\n[HEARTBEAT from {addr}]\n{json.dumps(event, indent=2)}")
                store_heartbeat(event)

            # --- Handle System/SubSystem/Config/Logging messages ---
            elif event_type == "system_status":
                if event_name.startswith("system_"):
                    etype = "SYSTEM"
                elif event_name.startswith("subsystem_"):
                    etype = "SUBSYSTEM"
                elif event_name.startswith("config_change_"):
                    etype = "CONFIG"
                elif event_name.startswith("logging_"):     # <-- added
                    etype = "LOGGING"                        # <-- added
                else:
                    etype = "UNKNOWN"

                print(f"\n[{etype} EVENT from {addr}]\n{json.dumps(event, indent=2)}")
                store_system_status(event)

            # --- Unknown event types ---
            else:
                # print(f"[DEBUG] Unknown event type received: {event_type}")
                print(f"Raw data: {data.decode('utf-8', errors='ignore')}")

    except KeyboardInterrupt:
        LOG.info("Heartbeat consumer stopped by user.")
        # print("\n[Consumer] Stopped by user.")
    except Exception as e:
        LOG.error(f"Heartbeat consumer error: {e}")
        print(f"[ERROR] Consumer encountered an exception: {e}")
    finally:
        sock.close()
        # LOG.info("UDP socket closed.")
        print("[Consumer] UDP socket closed.")


if __name__ == "__main__":
    main()
