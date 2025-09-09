import json
import logging
import psycopg2
from kafka import KafkaConsumer
from datetime import datetime
from helper import store_anomaly_to_database_and_siem

# === Kafka Config ===
KAFKA_TOPIC = "file-events"
BOOTSTRAP_SERVER = "localhost:9092"

consumer = KafkaConsumer(
    KAFKA_TOPIC,
    bootstrap_servers=BOOTSTRAP_SERVER,
    value_deserializer=lambda x: json.loads(x.decode('utf-8')),
    auto_offset_reset='latest'
)

# === PostgreSQL Config ===
DB_CONFIG = {
    'host': 'localhost',
    'user': 'postgres',
    'password': 'crl123',
    'dbname': 'anomalies_db'
}

# === Logging Setup ===
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("file_events_consumer.log"),
        logging.StreamHandler()
    ]
)

# === Sensitive Patterns or Paths ===
SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/ssh", "/boot",
    "C:\\Windows\\System32", "C:\\Users\\Public", ".env", "config.json", "secret"
]

SENSITIVE_KEYWORDS = ["confidential", "secret", "private", "backup"]

# === PostgreSQL insert ===
def log_to_postgres(event):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO file_events (timestamp, username, event_type, file_path, hostname, source_os)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                event["timestamp"],
                event["username"],
                event["event_type"],
                event["file_path"],
                event["hostname"],
                event["os"]
            )
        )
        conn.commit()
        cur.close()
        conn.close()
        logging.info("📁 File event stored in PostgreSQL.")
    except Exception as e:
        logging.error(f"PostgreSQL insert error: {e}")

# === Heuristic Anomaly Detection ===
def detect_file_anomaly(event):
    anomalies = []

    # Suspicious access/modification to critical files
    if any(sens.lower() in event["file_path"].lower() for sens in SENSITIVE_PATHS):
        anomalies.append({
            "Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS",
            "Event Sub Type": "SENSITIVE_FILE_TAMPERING",
            "Event Details": f"Sensitive file accessed or modified: {event['file_path']}"
        })

    # Suspicious deletions
    if event["event_type"] == "deleted" and any(keyword in event["file_path"].lower() for keyword in SENSITIVE_KEYWORDS):
        anomalies.append({
            "Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS",
            "Event Sub Type": "SUSPICIOUS_FILE_DELETION",
            "Event Details": f"Deleted potentially sensitive file: {event['file_path']}"
        })

    # Report anomaly
    if anomalies:
        alert = {
            "timestamp": event["timestamp"],
            "anomalies": anomalies,
            "metrics": {
                "username": event["username"],
                "file_path": event["file_path"],
                "event_type": event["event_type"],
                "hostname": event["hostname"],
                "mac_address": event.get("mac_address", "unknown"),
                "lan_ip": event.get("lan_ip", "unknown"),
            }
        }
        store_anomaly_to_database_and_siem(json.dumps(alert))
        logging.warning(f"⚠️ Anomaly Detected in File Access: {event['file_path']}")

# === Main ===
def main():
    logging.info(f"📡 Listening to Kafka topic: {KAFKA_TOPIC}")
    try:
        for message in consumer:
            event = message.value
            logging.info(f"File event: {event['event_type']} → {event['file_path']}")
            log_to_postgres(event)
            detect_file_anomaly(event)

    except KeyboardInterrupt:
        logging.info("Stopped by user.")
    except Exception as e:
        logging.error(f"Consumer error: {e}")
    finally:
        consumer.close()
        logging.info("Kafka consumer closed.")

if __name__ == "__main__":
    main()
