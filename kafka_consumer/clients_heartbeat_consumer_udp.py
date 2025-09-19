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
UDP_PORT = 6008   # 👈 assign a dedicated port for heartbeat

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
              AND last_seen < (NOW() - INTERVAL '2 minutes');
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


def main(stop_event=None):
    print("\033[1;32m  !!!!!!!!!!!Heartbeat Consumer started (UDP)!!!!!!!!!!!!!!\033[0m")
   
    LOG.info("Heartbeat consumer started (UDP)")

    try:
        while not (stop_event and stop_event.is_set()):
            data, addr = sock.recvfrom(65535)
            event = json.loads(data.decode("utf-8"))

            if event.get("type") != "heartbeat":
                continue

            print(f"\n[HEARTBEAT from {addr}]\n{json.dumps(event, indent=2)}")
            store_heartbeat(event)

    except KeyboardInterrupt:
        LOG.info("Heartbeat consumer stopped by user.")
    except Exception as e:
        LOG.error(f"Heartbeat consumer error: {e}")
    finally:
        sock.close()
        LOG.info("UDP socket closed.")

if __name__ == "__main__":
    main()
