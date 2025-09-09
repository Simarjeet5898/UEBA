import json
import logging
import psycopg2
from kafka import KafkaConsumer
from helper import store_anomaly_to_database_and_siem

KAFKA_TOPIC = "install-events"
BOOTSTRAP_SERVER = "localhost:9092"

consumer = KafkaConsumer(
    KAFKA_TOPIC,
    bootstrap_servers=BOOTSTRAP_SERVER,
    value_deserializer=lambda x: json.loads(x.decode("utf-8")),
    auto_offset_reset="latest"
)

DB_CONFIG = {
    "host": "localhost",
    "user": "postgres",
    "password": "crl123",
    "dbname": "anomalies_db"
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("install_activity_consumer.log"),
        logging.StreamHandler()
    ]
)

SUSPICIOUS_SOFTWARE = [
    "nmap", "netcat", "nc", "socat", "tor", "proxychains",
    "wireshark", "tcpdump", "hydra", "john", "aircrack"
]

def log_to_postgres(event):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO install_events (timestamp, username, event_type, application, hostname, source_os)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                event["timestamp"],
                event["username"],
                event["event_type"],
                event["application"],
                event["hostname"],
                event["os"]
            )
        )
        conn.commit()
        cur.close()
        conn.close()
        logging.info("Stored install event to PostgreSQL")
    except Exception as e:
        logging.error(f"Database insert error: {e}")

def detect_suspicious_installation(event):
    app = event["application"].lower()
    if event["event_type"] == "installed":
        for keyword in SUSPICIOUS_SOFTWARE:
            if keyword in app:
                alert = {
                    "timestamp": event["timestamp"],
                    "anomalies": [{
                        "Event Type": "SOFTWARE_ACTIVITY",
                        "Event Sub Type": "SUSPICIOUS_SOFTWARE_INSTALLED",
                        "Event Details": f"Installed software: {event['application']}"
                    }],
                    "metrics": {
                        "application": event["application"],
                        "username": event["username"],
                        "hostname": event["hostname"],
                        "mac_address": event.get("mac_address", "unknown"),
                        "lan_ip": event.get("lan_ip", "unknown")
                    }
                }
                store_anomaly_to_database_and_siem(json.dumps(alert))
                logging.warning(f"Suspicious software detected: {event['application']}")
                break

def main():
    logging.info(f"Listening to Kafka topic: {KAFKA_TOPIC}")
    try:
        for message in consumer:
            event = message.value
            logging.info(f"{event['event_type'].upper()} - {event['application']}")
            log_to_postgres(event)
            detect_suspicious_installation(event)
    except KeyboardInterrupt:
        logging.info("Stopped by user")
    except Exception as e:
        logging.error(f"Kafka consumer error: {e}")
    finally:
        consumer.close()
        logging.info("Kafka connection closed")

if __name__ == "__main__":
    main()
