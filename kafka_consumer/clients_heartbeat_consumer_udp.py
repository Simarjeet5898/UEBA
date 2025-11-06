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

def store_heartbeat(event):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # 1. Create table if not exists
        cur.execute("""
            CREATE TABLE IF NOT EXISTS client_status (
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
            INSERT INTO client_status (client_id, last_seen, status)
            VALUES (%s, %s, %s)
            ON CONFLICT (client_id) DO UPDATE
            SET last_seen = EXCLUDED.last_seen,
                status = EXCLUDED.status;   -- respect producer status
        """, (client_id, last_seen, status))

        # 3. Mark old clients inactive (> 2 min, only if still active)
        cur.execute("""
            UPDATE client_status
            SET status = 'inactive'
            WHERE status='active'
              AND last_seen < (NOW() - INTERVAL '10 seconds');
        """)

        # 4. Count active clients
        cur.execute("SELECT COUNT(*) FROM client_status WHERE status='active';")
        active_count = cur.fetchone()[0]

        conn.commit()
        cur.close()
        conn.close()

        LOG.info(f"Heartbeat stored for client {client_id} at {last_seen} (status={status})")
        print(f"[Heartbeat Consumer] Total active clients = {active_count}")

    except Exception as e:
        LOG.error(f"Client status insert error: {e}")


# def store_system_status(event):
#     """Store or update system and subsystem status messages in a separate table."""
#     try:
#         conn = psycopg2.connect(**DB_CONFIG)
#         cur = conn.cursor()

#         # === Ensure table exists ===
#         cur.execute("""
#             CREATE TABLE IF NOT EXISTS system_status (
#                 id SERIAL PRIMARY KEY,
#                 client_id TEXT,
#                 event TEXT,                -- clean event/service name
#                 event_type TEXT,           -- 'system' or 'subsystem'
#                 status TEXT NULL,          -- active/inactive for subsystems only
#                 timestamp TIMESTAMP,
#                 boot_time TIMESTAMP NULL,  -- only for startup
#                 close_time TIMESTAMP NULL, -- only for shutdown/reboot/abort
#                 UNIQUE (client_id, event)
#             );
#         """)

#         # --- Extract core fields ---
#         client_id = event.get("client_id", "unknown")
#         raw_event = event.get("event", "unknown")
#         timestamp_str = event.get("timestamp")
#         ts = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

#         # --- Determine event type and clean name ---
#         if raw_event.startswith("system_"):
#             event_type = "system"
#             event_name = raw_event.replace("system_", "")
#             status = None

#             # --- Decide whether this is startup or shutdown/reboot/abort ---
#             boot_time = None
#             close_time = None
#             if event_name == "startup":
#                 boot_time = ts
#             elif event_name in ("shutdown", "abort", "reboot"):
#                 close_time = ts

#         elif raw_event.startswith("subsystem_"):
#             event_type = "subsystem"
#             event_name = raw_event.replace("subsystem_", "")
#             status = None
#             boot_time = None
#             close_time = None

#             # Parse subsystem variations
#             if event_name.startswith("init_"):
#                 core = event_name.replace("init_", "")
#                 if core.endswith("_active"):
#                     status = "active"
#                     event_name = core.replace("_active", "")
#                 elif core.endswith("_inactive"):
#                     status = "inactive"
#                     event_name = core.replace("_inactive", "")
#                 else:
#                     event_name = core
#             elif event_name.startswith("startup_"):
#                 status = "active"
#                 event_name = event_name.replace("startup_", "")
#             elif event_name.startswith("shutdown_"):
#                 status = "inactive"
#                 event_name = event_name.replace("shutdown_", "")
#             else:
#                 status = "unknown"

#         else:
#             event_type = "unknown"
#             event_name = raw_event
#             status = None
#             boot_time = None
#             close_time = None

#         # === UPSERT ===
#         cur.execute("""
#             INSERT INTO system_status (client_id, event, event_type, status, timestamp, boot_time, close_time)
#             VALUES (%s, %s, %s, %s, %s, %s, %s)
#             ON CONFLICT (client_id, event)
#             DO UPDATE SET
#                 status = EXCLUDED.status,
#                 timestamp = EXCLUDED.timestamp,
#                 boot_time = COALESCE(EXCLUDED.boot_time, system_status.boot_time),
#                 close_time = COALESCE(EXCLUDED.close_time, system_status.close_time);
#         """, (client_id, event_name, event_type, status, ts, boot_time, close_time))

#         conn.commit()
#         cur.close()
#         conn.close()

#         print(f"[SystemStatus Consumer] Upserted {event_type}: {event_name} ({status}) for {client_id}")

#     except Exception as e:
#         LOG.error(f"System status insert/update error: {e}")

def store_system_status(event):
    """Store or update system, subsystem, and configuration change events."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # === Ensure table exists ===
        cur.execute("""
            CREATE TABLE IF NOT EXISTS system_status (
                id SERIAL PRIMARY KEY,
                client_id TEXT,
                event TEXT,                 -- clean event/service/config name
                event_type TEXT,            -- 'system', 'subsystem', or 'config_change'
                status TEXT NULL,           -- active/inactive (for subsystems)
                timestamp TIMESTAMP,
                boot_time TIMESTAMP NULL,   -- only for startup
                close_time TIMESTAMP NULL,  -- only for shutdown/reboot/abort
                UNIQUE (client_id, event)
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
        boot_time = None
        close_time = None

        # === Handle SYSTEM events ===
        if raw_event.startswith("system_"):
            event_type = "system"
            event_name = raw_event.replace("system_", "")

            if event_name == "startup":
                boot_time = ts
            elif event_name in ("shutdown", "abort", "reboot"):
                close_time = ts

        # === Handle SUBSYSTEM events ===
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

        # === Handle CONFIG CHANGE events ===
        elif raw_event.startswith("config_change_"):
            event_type = "config_change"
            event_name = raw_event.replace("config_change_", "")
            status = None  # no active/inactive state
            boot_time = None
            close_time = None

        # === Unknown events ===
        else:
            event_type = "unknown"
            event_name = raw_event

        # === UPSERT (insert or update) ===
        cur.execute("""
            INSERT INTO system_status (client_id, event, event_type, status, timestamp, boot_time, close_time)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (client_id, event)
            DO UPDATE SET
                status = EXCLUDED.status,
                timestamp = EXCLUDED.timestamp,
                boot_time = COALESCE(EXCLUDED.boot_time, system_status.boot_time),
                close_time = COALESCE(EXCLUDED.close_time, system_status.close_time);
        """, (client_id, event_name, event_type, status, ts, boot_time, close_time))

        conn.commit()
        cur.close()
        conn.close()

        print(f"[SystemStatus Consumer] Upserted {event_type}: {event_name} ({status}) for {client_id}")

    except Exception as e:
        LOG.error(f"System status insert/update error: {e}")




# def main(stop_event=None):
#     print("\033[1;32m  !!!!!!!!!!!Heartbeat Consumer started (UDP)!!!!!!!!!!!!!!\033[0m")
#     LOG.info("Heartbeat consumer started (UDP)")

#     try:
#         while not (stop_event and stop_event.is_set()):
#             data, addr = sock.recvfrom(65535)
#             event = json.loads(data.decode("utf-8"))

#             event_type = event.get("type")

#             # --- Handle Heartbeat messages ---
#             if event_type == "heartbeat":
#                 print(f"\n[HEARTBEAT from {addr}]\n{json.dumps(event, indent=2)}")
#                 store_heartbeat(event)

#             # --- Handle System/SubSystem messages ---
#             elif event_type == "system_status":
#                 # Determine if it's system or subsystem for better display
#                 event_name = event.get("event", "unknown")
#                 if event_name.startswith("system_"):
#                     etype = "SYSTEM"
#                 elif event_name.startswith("subsystem_"):
#                     etype = "SUBSYSTEM"
#                 else:
#                     etype = "UNKNOWN"

#                 print(f"\n[{etype} EVENT from {addr}]\n{json.dumps(event, indent=2)}")
#                 store_system_status(event)

#             # --- Unknown event types ---
#             else:
#                 print(f"[DEBUG] Unknown event type received: {event_type}")

#     except KeyboardInterrupt:
#         LOG.info("Heartbeat consumer stopped by user.")
#     except Exception as e:
#         LOG.error(f"Heartbeat consumer error: {e}")
#     finally:
#         sock.close()
#         LOG.info("UDP socket closed.")

def main(stop_event=None):
    print("\033[1;32m  !!!!!!!!!!!Heartbeat Consumer started (UDP)!!!!!!!!!!!!!!\033[0m")
    LOG.info("Heartbeat consumer started (UDP)")

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

            # --- Handle System/SubSystem/Config messages ---
            elif event_type == "system_status":
                if event_name.startswith("system_"):
                    etype = "SYSTEM"
                elif event_name.startswith("subsystem_"):
                    etype = "SUBSYSTEM"
                elif event_name.startswith("config_change_"):
                    etype = "CONFIG"
                else:
                    etype = "UNKNOWN"

                print(f"\n[{etype} EVENT from {addr}]\n{json.dumps(event, indent=2)}")
                store_system_status(event)

            # --- Unknown event types ---
            else:
                print(f"[DEBUG] Unknown event type received: {event_type}")
                print(f"Raw data: {data.decode('utf-8', errors='ignore')}")

    except KeyboardInterrupt:
        LOG.info("Heartbeat consumer stopped by user.")
        print("\n[Consumer] Stopped by user.")
    except Exception as e:
        LOG.error(f"Heartbeat consumer error: {e}")
        print(f"[ERROR] Consumer encountered an exception: {e}")
    finally:
        sock.close()
        LOG.info("UDP socket closed.")
        print("[Consumer] UDP socket closed.")



if __name__ == "__main__":
    main()
