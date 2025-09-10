import os
import json
import logging
import psycopg2
from kafka import KafkaConsumer
from datetime import datetime

# ─── Configuration ─────────────────────────────────────────────────────────────
KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "localhost:9092")
KAFKA_TOPIC  = "privileged_user_metrics"

DB_CONFIG = {
    'host':     'localhost',
    'user':     'postgres',
    'password': 'crl123',
    'database': 'anomalies_db'
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ─── Postgres Setup ────────────────────────────────────────────────────────────
TABLE_NAME = "privilege_user_monitoring"

def init_db():
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
      id              SERIAL PRIMARY KEY,
      ts              TIMESTAMP     NOT NULL,
      username        TEXT          NOT NULL,
      user_type       TEXT          NOT NULL,
      device_mac      TEXT          NOT NULL,
      login_time      TIMESTAMP     NULL,
      logout_time     TIMESTAMP     NULL,
      commands        JSONB         NULL,
      file_access     JSONB         NULL
    );
    """)
    conn.commit()
    return conn

# ─── Kafka Consumer ────────────────────────────────────────────────────────────
def run_consumer():
    conn = init_db()
    cur  = conn.cursor()

    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=[KAFKA_BROKER],
        value_deserializer=lambda m: json.loads(m.decode('utf-8')),
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id="priv-user-monitor-group"
    )
    logging.info(f"Listening for events on topic '{KAFKA_TOPIC}'…")

    for message in consumer:
        raw = message.value
        # normalize into a list of event dicts
        if isinstance(raw, list):
            events = raw
        elif isinstance(raw, dict):
            events = [raw]
        else:
            logging.error(f"Unexpected message format: {raw!r}")
            continue

        for ev in events:
            # parse timestamps
            try:
                ts        = datetime.fromisoformat(ev["timestamp"])
                login_ts  = ev.get("login_time")  and datetime.fromisoformat(ev["login_time"])
                logout_ts = ev.get("logout_time") and datetime.fromisoformat(ev["logout_time"])
            except Exception as e:
                logging.error(f"Timestamp parse error: {e} -- {ev}")
                continue

            # prepare JSONB fields
            commands = json.dumps(ev.get("commands", []))
            files    = json.dumps(ev.get("file_access", []))

            # insert
            cur.execute(f"""
                INSERT INTO {TABLE_NAME}
                  (ts, username, user_type, device_mac, login_time, logout_time, commands, file_access)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                ts,
                ev.get("user"),
                ev.get("user_type"),
                ev.get("device_mac"),
                login_ts,
                logout_ts,
                commands,
                files
            ))
        conn.commit()
        logging.info(f"Committed {len(events)} event(s) to DB")


if __name__ == "__main__":
    run_consumer()
