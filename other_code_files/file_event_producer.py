import os
import json
import time
import socket
import uuid
import psutil
import platform
import logging
from datetime import datetime
from kafka import KafkaProducer
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# === Config ===
KAFKA_TOPIC = "file-events"
BOOTSTRAP_SERVERS = ["localhost:9092"]
MONITOR_DIRS = [os.path.expanduser("~")]  # You can add more paths

# === Init Logging ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# === Kafka Producer ===
producer = KafkaProducer(
    bootstrap_servers=BOOTSTRAP_SERVERS,
    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
    compression_type='gzip',
    acks='all',
    linger_ms=500
)

# === System Info ===
def get_system_info():
    lan_ip = None
    for iface_addrs in psutil.net_if_addrs().values():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                lan_ip = addr.address
                break
        if lan_ip:
            break

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "username": psutil.users()[0].name if psutil.users() else "Unknown",
        "hostname": socket.gethostname(),
        "mac_address": ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(40, -1, -8)]),
        "lan_ip": lan_ip or "Unknown",
        "os": platform.system()
    }

# === File Watcher Handler ===
class FileActivityHandler(FileSystemEventHandler):
    def process_event(self, event, event_type):
        if not event.is_directory:
            try:
                file_event = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "event_type": event_type,
                    "file_path": os.path.normpath(event.src_path),
                    **get_system_info()
                }
                producer.send(KAFKA_TOPIC, value=file_event)
                logging.info(f"📄 {event_type.upper()} - {event.src_path}")
            except Exception as e:
                logging.error(f"Error sending file event: {e}")

    def on_created(self, event):
        self.process_event(event, "created")

    def on_modified(self, event):
        self.process_event(event, "modified")

    def on_deleted(self, event):
        self.process_event(event, "deleted")

    def on_moved(self, event):
        self.process_event(event, "moved")

# === Run Watcher ===
def main():
    observers = []
    try:
        for path in MONITOR_DIRS:
            if os.path.exists(path):
                logging.info(f"🔍 Watching directory: {path}")
                event_handler = FileActivityHandler()
                observer = Observer()
                observer.schedule(event_handler, path, recursive=True)
                observer.start()
                observers.append(observer)
            else:
                logging.warning(f"❌ Path does not exist: {path}")

        while True:
            time.sleep(5)

    except KeyboardInterrupt:
        logging.info("Interrupted by user.")
    finally:
        for obs in observers:
            obs.stop()
        for obs in observers:
            obs.join()
        logging.info("✅ File access producer stopped.")

if __name__ == "__main__":
    main()
