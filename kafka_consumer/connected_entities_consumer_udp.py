"""
Connected Entities Consumer Script
----------------------------------

This script serves as the consumer in a Kafka-based pipeline for monitoring 
connected hardware entities on a Linux system. It listens to the 'device-events' 
Kafka topic, parses JSON-formatted device metadata, and stores the data in a 
PostgreSQL database (`connected_entities_ueba` table) for centralized monitoring 
and further analysis.

Key Features:
- Kafka consumer integration for real-time event ingestion
- JSON deserialization and structured event processing
- PostgreSQL storage of device connection/disconnection events
- Automatic creation of the target table if it doesn't exist
- Handles session duration and timestamps for behavioral analysis

Dependencies:
- Kafka (via kafka-python)
- psycopg2 (PostgreSQL adapter for Python)
- PostgreSQL server with appropriate credentials
- Assumes a matching producer is populating the `device-events` topic

Usage:
- Run this consumer script as a background service or system agent
- Works in conjunction with the connected entity producer

Author: []
Date: []
"""

import json
import psycopg2
# from kafka import KafkaConsumer
import socket
import logging
LOG = logging.getLogger("Connected Entities Consumer")
# ─── Config ─────────────────────────────────────────────────────


CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
# UDP_PORT = config["udp"]["server_port"]
UDP_PORT = 6006

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((UDP_IP, UDP_PORT))

DB_CONFIG = {
    'host': config["local_db"]["host"],
    'user': config["local_db"]["user"],
    'password': config["local_db"]["password"],
    'dbname': config["local_db"]["dbname"]
}

def ensure_table(conn):
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS connected_entities_ueba (
        id SERIAL PRIMARY KEY,

        username        TEXT,
        timestamp       TIMESTAMP,
        snapshot_date   DATE GENERATED ALWAYS AS (timestamp::date) STORED,  -- ⬅ per-day key
        hostname        TEXT,
        mac_address     TEXT,

        vendor_id       TEXT,
        product_id      TEXT,
        vendor_name     TEXT,
        product_name    TEXT,
        serial_number   TEXT,

        busnum          TEXT,
        devnum          TEXT,
        device_type     TEXT,
        device_node     TEXT,
        sys_name        TEXT,
        driver          TEXT,
        usb_version     TEXT,
        speed           TEXT,

        connection_status    TEXT,
        session_start_time   TIMESTAMP,
        session_duration_sec INTEGER,

        CONSTRAINT connected_entities_active_unique UNIQUE (
            username,
            hostname,
            mac_address,
            vendor_id,
            product_id,
            busnum,
            devnum,
            device_type,
            product_name,
            snapshot_date,          
            connection_status
        )
    );
    """)


    conn.commit()
    cur.close()


def insert_device_event(conn, data):
    cur = conn.cursor()

    if data["connection_status"] == "connected":
        insert_sql = """
            INSERT INTO connected_entities_ueba (
                username, timestamp, hostname, mac_address,
                vendor_id, product_id, vendor_name, product_name, serial_number,
                busnum, devnum, device_type, device_node, sys_name, driver,
                usb_version, speed, connection_status, session_start_time, session_duration_sec
            ) VALUES (
                %(username)s, %(timestamp)s, %(hostname)s, %(mac_address)s,
                %(vendor_id)s, %(product_id)s, %(vendor_name)s, %(product_name)s, %(serial_number)s,
                %(busnum)s, %(devnum)s, %(device_type)s, %(device_node)s, %(sys_name)s, %(driver)s,
                %(usb_version)s, %(speed)s, %(connection_status)s, %(session_start_time)s, %(session_duration_sec)s
            )
            ON CONFLICT ON CONSTRAINT connected_entities_active_unique
            DO NOTHING;
        """

        cur.execute(insert_sql, data)

    elif data["connection_status"] == "disconnected":
        update_sql = """
            UPDATE connected_entities_ueba ce
            SET connection_status = 'disconnected',
                session_duration_sec = %(session_duration_sec)s
            WHERE ce.id = (
                SELECT id FROM connected_entities_ueba
                WHERE username = %(username)s
                AND hostname = %(hostname)s
                AND mac_address = %(mac_address)s
                AND vendor_id = %(vendor_id)s
                AND product_id = %(product_id)s
                AND busnum = %(busnum)s
                AND devnum = %(devnum)s
                AND device_type = %(device_type)s
                AND product_name = %(product_name)s
                AND connection_status = 'connected'
                ORDER BY timestamp DESC
                LIMIT 1
            );
        """


        cur.execute(update_sql, data)

    conn.commit()
    cur.close()

   
def main(stop_event=None):

    conn = psycopg2.connect(**DB_CONFIG)
    ensure_table(conn)
    print("\033[1;92m!!!!!!!!! Connected Entities Consumer running (UDP) !!!!!!\033[0m")
    LOG.info("!!!!!!!!! Connected Entities Consumer running (UDP) !!!!!!")

    try:
        # while True:
        
        while not (stop_event and stop_event.is_set()):
            data, addr = sock.recvfrom(65535)   # listen for UDP packets
            event = json.loads(data.decode("utf-8"))

            # filter so only device-events go here
            if event.get("topic") == "device-events":
                LOG.info(
                    "[ConnectedEntities received] mac=%s product=%s type=%s status=%s",
                    event.get("mac_address"),
                    event.get("product_name"),
                    event.get("device_type"),
                    event.get("connection_status"),
                )
                print(f"[CONSUMED EVENT from {addr}]\n{json.dumps(event, indent=2)}")
                insert_device_event(conn, event)

    except KeyboardInterrupt:
        print("\nConsumer stopped by user.")
    except Exception as e:
        LOG.error(f"UDP consumer error: {e}")
    finally:
        sock.close()
        conn.close()
        LOG.info("UDP consumer closed.")


if __name__ == "__main__":
    main()
