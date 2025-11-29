import socket
import json
import psycopg2
import logging
from datetime import datetime


CONFIG_PATH = "/home/config.json"

with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

UDP_IP   = config["udp"]["server_ip"]
UDP_PORT = 6009


DB_CONFIG = {
    'host': config["local_db"]["host"],
    'user': config["local_db"]["user"],
    'password': config["local_db"]["password"],
    'dbname': config["local_db"]["dbname"]
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def init_db():
    conn = psycopg2.connect(**DB_CONFIG)
    cur  = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS privileged_user_list_ueba (
            id SERIAL PRIMARY KEY,
            username        TEXT NOT NULL,
            device_mac      TEXT NOT NULL,
            hostname        TEXT NOT NULL,
            detected_at     TIMESTAMP NOT NULL,
            account_type    TEXT NOT NULL,
            action          TEXT,
            UNIQUE(username, device_mac, hostname)
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS privileged_user_monitoring_ueba (
            id SERIAL PRIMARY KEY,
            username        TEXT NOT NULL,
            device_mac      TEXT NOT NULL,
            hostname        TEXT NOT NULL,
            event_type      TEXT NOT NULL,
            command_executed TEXT,
            file_accessed   TEXT,
            timestamp       TIMESTAMP NOT NULL,
            source          TEXT,
            UNIQUE(username, device_mac, hostname, event_type, timestamp)
        );
    """)


    conn.commit()
    return conn


def main(stop_event=None):
    import logging
    import threading
    import time

    print("\033[1;32m  !!!!!!!!!!!Privilege User Monitoring Consumer started !!!!!!!!!!!!!!\033[0m")

    logger = logging.getLogger()       
    logger.handlers = []               
    logger.propagate = False

    log = logging.getLogger("privileged_user_consumer")
    log.setLevel(logging.INFO)

    conn = init_db()
    cur  = conn.cursor()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    # Instead of printing → write to log file
    log.info(f"Listening for UDP privileged user packets on {UDP_IP}:{UDP_PORT}")

    while stop_event is None or not stop_event.is_set():

        try:
            raw_data, addr = sock.recvfrom(65535)
            payload = json.loads(raw_data.decode("utf-8"))
        except Exception as e:
            log.error(f"JSON decode error: {e}")
            continue

        if "privileged_users" not in payload:
            log.error(f"Missing privileged_users field: {payload}")
            continue

        users      = payload["privileged_users"]
        mac        = payload.get("mac_address")
        hostname   = payload.get("hostname")
        timestamp  = payload.get("timestamp")

        try:
            detected_at = datetime.fromisoformat(timestamp)
        except Exception:
            detected_at = datetime.now()

        events = payload.get("events", []) or []
        user_action_map = {}

        # privilege_added / removal detection
        for ev in events:
            et = ev.get("event_type")
            u  = ev.get("user")
            if not u or not et:
                continue

            if et == "privilege_added":
                user_action_map[u] = "privilege_escalation"
            elif et == "privilege_removed":
                user_action_map[u] = "privilege_removal"

        # handle privilege_removed for users no longer in list
        for ev in events:
            if ev.get("event_type") != "privilege_removed":
                continue

            u = ev.get("user")
            if not u:
                continue
            if u in users:
                continue

            try:
                cur.execute("""
                    UPDATE privileged_user_list_ueba
                       SET action = %s,
                           detected_at = %s
                     WHERE username = %s AND device_mac = %s AND hostname = %s
                """, ("privilege_removal", detected_at, u, mac, hostname))

                if cur.rowcount == 0:
                    cur.execute("""
                        INSERT INTO privileged_user_list_ueba
                            (username, device_mac, hostname, detected_at, account_type, action)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT(username, device_mac, hostname)
                        DO UPDATE SET
                            detected_at = EXCLUDED.detected_at,
                            account_type = EXCLUDED.account_type,
                            action = EXCLUDED.action;
                    """, (
                        u,
                        mac,
                        hostname,
                        detected_at,
                        payload.get("metadata", {}).get(u, {}).get("account_type", "unknown"),
                        "privilege_removal"
                    ))
            except Exception as e:
                log.error(f"DB update/insert error for removed user {u}: {e}")

        # update/insert current privileged users
        for uname in users:
            try:
                action = user_action_map.get(uname)

                if action is not None:
                    cur.execute("""
                        INSERT INTO privileged_user_list_ueba
                            (username, device_mac, hostname, detected_at, account_type, action)
                        VALUES(%s, %s, %s, %s, %s, %s)
                        ON CONFLICT(username, device_mac, hostname)
                        DO UPDATE SET
                            detected_at = EXCLUDED.detected_at,
                            account_type = EXCLUDED.account_type,
                            action = EXCLUDED.action;
                    """, (
                        uname,
                        mac,
                        hostname,
                        detected_at,
                        payload.get("metadata", {}).get(uname, {}).get("account_type", "unknown"),
                        action
                    ))
                else:
                    cur.execute("""
                        INSERT INTO privileged_user_list_ueba
                            (username, device_mac, hostname, detected_at, account_type)
                        VALUES(%s, %s, %s, %s, %s)
                        ON CONFLICT(username, device_mac, hostname)
                        DO UPDATE SET
                            detected_at = EXCLUDED.detected_at,
                            account_type = EXCLUDED.account_type;
                    """, (
                        uname,
                        mac,
                        hostname,
                        detected_at,
                        payload.get("metadata", {}).get(uname, {}).get("account_type", "unknown")
                    ))
            except Exception as e:
                log.error(f"DB insert error for user {uname}: {e}")

        # command_executed logging
        for ev in events:
            if ev.get("event_type") != "command_executed":
                continue
            u = ev.get("user")
            if not u:
                continue
            try:
                cur.execute("""
                    INSERT INTO privileged_user_monitoring_ueba
                        (username, device_mac, hostname, event_type, command_executed, timestamp, source)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING;
                """, (
                    u,
                    mac,
                    hostname,
                    "command_executed",
                    ev.get("details"),
                    ev.get("timestamp", datetime.now().isoformat()),
                    ev.get("source", "bash_history")
                ))
            except Exception as e:
                log.error(f"Failed to log command execution event for {u}: {e}")

        conn.commit()
        log.info(f"Updated privileged list for {len(users)} users from {hostname}@{mac}")


if __name__ == "__main__":
    main()
