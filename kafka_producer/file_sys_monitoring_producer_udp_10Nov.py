import os
import json
import time
import uuid
import logging
from datetime import datetime
from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler
import psutil
import socket
import ipaddress
import sys
import hashlib

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from kafka_producer.new_log_monitor import get_lan_and_internet_ips

CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH) as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
UDP_PORT = config["udp"]["server_port"]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

IGNORE_PATTERNS = [".1", ".gz", ".old", ".bak", ".swp", ".tmp", ".swo", ".swx", ".log",".bash_history"]
IGNORE_DIRS = [
    "/proc", "/sys", "/dev",
    os.path.expanduser("~/.config"),
    os.path.expanduser("~/.cache"),
    os.path.expanduser("~/.pgadmin"),
    os.path.expanduser("~/.local")
]
IGNORE_DIRS = [os.path.realpath(d) for d in IGNORE_DIRS]

EVENT_MAPPING = {
    "created":  {"Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS", "Event Sub Type": "FILE_CREATION",    "Event Details": "New file created in the directory"},
    "deleted":  {"Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS", "Event Sub Type": "FILE_DELETION",    "Event Details": "File deleted in the directory"},
    "modified": {"Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS", "Event Sub Type": "FILE_MODIFICATION", "Event Details": "File modified in the directory"},
    "moved":    {"Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS", "Event Sub Type": "FILE_MOVED",        "Event Details": "File moved or renamed in the directory"}
}

USERNAME = psutil.users()[0].name if psutil.users() else "Unknown"

def get_lan_and_internet_ips():
    lan_ip = None
    internet_ip = None
    for iface_addrs in psutil.net_if_addrs().values():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
                if not ip.startswith("127.") and ipaddress.ip_address(ip).is_private:
                    lan_ip = ip
                    break
        if lan_ip:
            break
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        internet_ip = s.getsockname()[0]
        s.close()
    except Exception:
        internet_ip = "Unknown"
    return lan_ip or "Unknown", internet_ip or "Unknown"

lan_ip, internet_ip = get_lan_and_internet_ips()
hostname = os.uname().nodename
mac_address = ':'.join(f"{(uuid.getnode() >> i) & 0xff:02x}" for i in range(40, -1, -8))

class DirectoryMonitor(FileSystemEventHandler):

    def should_ignore(self, path):
        real_path = os.path.realpath(path)
        for ignored in IGNORE_DIRS:
            if os.path.commonpath([real_path, ignored]) == ignored:
                return True
        if "BraveSoftware/Brave-Browser" in real_path:
            return True
        if "/snap/" in real_path:
            return True
        filename = os.path.basename(real_path)
        if any(filename.endswith(pat) for pat in IGNORE_PATTERNS):
            return True
        if filename.startswith(".goutputstream-"):
            return True
        return False

    def compute_file_hash(self, path):
        try:
            if not os.path.isfile(path):
                return None
            hasher = hashlib.sha256()
            with open(path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logging.warning(f"Failed to hash file {path}: {e}")
            return None

    def on_any_event(self, event):
        if event.is_directory or self.should_ignore(event.src_path):
            return

        event_type = event.event_type
        if event_type not in EVENT_MAPPING:
            return

        info = EVENT_MAPPING[event_type]

        if event_type == "moved":
            trash_path = os.path.expanduser("~/.local/share/Trash/files")
            if getattr(event, "dest_path", "").startswith(trash_path):
                event_type = "deleted"
                event = type('Event', (object,), {
                    "event_type": "deleted",
                    "src_path": event.src_path,
                    "is_directory": False
                })()

        if event_type == "moved":
            event_info = {
                "Event Type": info["Event Type"],
                "Event Sub Type": info["Event Sub Type"],
                "Event Details": f"{info['Event Details']}: from {event.src_path} to {event.dest_path} on host {hostname}",
                "Value": {"from": event.src_path, "to": event.dest_path}
            }
        else:
            event_info = {
                "Event Type": info["Event Type"],
                "Event Sub Type": info["Event Sub Type"],
                "Event Details": f"{info['Event Details']} at {event.src_path} on host {hostname}",
                "Value": event.src_path
            }

        file_hash = None
        if event_type == "modified":
            file_hash = self.compute_file_hash(event.src_path)

        metrics = {
            "timestamp": datetime.now().isoformat(),
            "hostname": hostname,
            "mac_address": mac_address,
            "username": USERNAME,
            "ip_addresses": get_lan_and_internet_ips(),
            "directory": event.src_path,
            "event_type": event_type,
            "file_hash": file_hash
        }

        event_data = {
            "timestamp": metrics["timestamp"],
            "username": metrics["username"],
            "event_info": event_info,
            "metrics": metrics,
            "topic": "sensitive-events"
        }

        sock.sendto(json.dumps(event_data).encode("utf-8"), (UDP_IP, UDP_PORT))
        print(f"[UDP] Sent: {event_type} at {event.src_path}")

def load_monitoring_config():
    try:
        monitored = [d for d in config.get("monitored_dirs", []) if os.path.exists(d)]
        sensitive = [d for d in config.get("sensitive_dirs", []) if os.path.exists(d)]
        return monitored, sensitive
    except Exception as e:
        logging.error(f"Failed to load config: {e}")
        return [], []

def main():
    print("\033[1;92m!!!!!!!!! File System Monitoring Producer Running!!!!!!\033[0m")
    monitored_dirs, _ = load_monitoring_config()

    if not monitored_dirs:
        print("No valid monitored directories found. Exiting.")
        return

    handler = DirectoryMonitor()
    observer = Observer()
    for d in monitored_dirs:
        print(f"Watching: {d}")
        observer.schedule(handler, d, recursive=True)
    observer.start()
    print("Watcher started.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
