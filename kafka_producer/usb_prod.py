
import os
import time
import json
import logging
import psutil
import uuid
from datetime import datetime
from kafka import KafkaProducer
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pdfminer.high_level import extract_text as extract_pdf_text
from docx import Document
import socket
import ipaddress


# === Configuration ===
USB_TOPIC = 'usb-transfers'
# BOOTSTRAP_SERVER = '10.229.40.140:9092'
BOOTSTRAP_SERVER = 'localhost:9092'
SCAN_INTERVAL = 5  # seconds



def get_lan_and_internet_ips():
    lan_ip = None
    internet_ip = None

    # 1. Find LAN IP (private, non-loopback)
    for iface_addrs in psutil.net_if_addrs().values():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
                if not ip.startswith("127.") and ipaddress.ip_address(ip).is_private:
                    lan_ip = ip
                    break
        if lan_ip:
            break

    # 2. Find Internet IP (via socket routing)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        internet_ip = s.getsockname()[0]
        s.close()
    except Exception:
        internet_ip = "Unknown"

    return lan_ip or "Unknown", internet_ip or "Unknown"

# Example usage
lan_ip, internet_ip = get_lan_and_internet_ips()


# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

producer = KafkaProducer(
    bootstrap_servers=BOOTSTRAP_SERVER,
    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
    compression_type='gzip',
    acks='all',
    linger_ms=500
)

def get_usb_mounts():
    mounts = []
    for part in psutil.disk_partitions():
        if '/dev/sd' in part.device and ('/media' in part.mountpoint or '/run/media' in part.mountpoint):
            mounts.append({
                'device': part.device,
                'mountpoint': part.mountpoint,
                'fstype': part.fstype
            })
    return mounts

def get_system_info():
    return {
        "username": psutil.users()[0].name if psutil.users() else "Unknown",
        "hostname": os.uname().nodename if hasattr(os, 'uname') else "Unknown",
        "mac_address": ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(40, -1, -8)]),
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        # "ip_addresses": get_lan_and_internet_ips
        "ip_addresses": get_lan_and_internet_ips()

    }

def extract_text_snippet(file_path):
    try:
        if file_path.endswith('.txt'):
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read(2000)
        elif file_path.endswith('.pdf'):
            return extract_pdf_text(file_path)[:500]
        elif file_path.endswith('.docx'):
            doc = Document(file_path)
            return ' '.join(p.text for p in doc.paragraphs)[:500]
    except Exception as e:
        logging.warning(f"Text extract failed from {file_path}: {e}")
    return None

class USBFileEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return

        file_path = event.src_path
        snippet = extract_text_snippet(file_path)

        if snippet:
            try:
                usb_mounts = get_usb_mounts()
                system_info = get_system_info()

                message = {
                    "direction": "to_usb",
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "filename": os.path.basename(file_path),
                    "filepath": file_path,
                    "size_bytes": os.path.getsize(file_path),
                    "content_snippet": snippet,
                    "usb_mounts": usb_mounts,
                    "system_info": system_info
                }

                logging.info(f"USB event: {message}")
                producer.send(USB_TOPIC, value=message)

            except Exception as e:
                logging.error(f"Error in USB event processing: {e}")

class USBWatcher:
    def __init__(self):
        self.observers = {}
        self.previous_mounts = set()

    def check_and_watch(self):
        current_mounts = {
            p.mountpoint: p.device
            for p in psutil.disk_partitions()
            if '/dev/sd' in p.device and ('/media' in p.mountpoint or '/run/media' in p.mountpoint)
        }

        new_mounts = set(current_mounts.keys()) - self.previous_mounts
        for mount in new_mounts:
            self.watch_mount(mount)

        self.previous_mounts = set(current_mounts.keys())

    def watch_mount(self, mount_point):
        handler = USBFileEventHandler()
        observer = Observer()
        observer.schedule(handler, mount_point, recursive=True)
        observer.start()
        self.observers[mount_point] = observer
        logging.info(f"Started monitoring mount: {mount_point}")

    def run(self):
        try:
            while True:
                self.check_and_watch()
                time.sleep(SCAN_INTERVAL)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        for observer in self.observers.values():
            observer.stop()
        for observer in self.observers.values():
            observer.join()

if __name__ == '__main__':
    watcher = USBWatcher()
    watcher.run()
