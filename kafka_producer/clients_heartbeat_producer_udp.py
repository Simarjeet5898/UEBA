import socket
import json
import time
import uuid
import signal
import sys
import os
from datetime import datetime

CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
UDP_PORT = config["udp"]["server_port"]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# === Use hostname + MAC as client_id ===
hostname = socket.gethostname()
mac_addr = hex(uuid.getnode())[2:]  # remove '0x' prefix
CLIENT_ID = f"{hostname}_{mac_addr}"

running = True  # flag for loop

def send_heartbeat():
    while running:
        msg = {
            "type": "heartbeat",
            "client_id": CLIENT_ID,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "active"
        }
        sock.sendto(json.dumps(msg).encode(), (UDP_IP, UDP_PORT))
        time.sleep(30)

def send_shutdown():
    """Send one last heartbeat marking client inactive before exit."""
    msg = {
        "type": "heartbeat",
        "client_id": CLIENT_ID,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "inactive"
    }
    try:
        sock.sendto(json.dumps(msg).encode(), (UDP_IP, UDP_PORT))
        print(f"[UEBA Client] Sent shutdown heartbeat for {CLIENT_ID}")
    except Exception as e:
        print(f"[UEBA Client] Failed to send shutdown heartbeat: {e}")

def handle_exit(signum, frame):
    global running
    print(f"\n[UEBA Client] Signal {signum} received, shutting down...")
    running = False
    send_shutdown()
    os._exit(0)

# Trap Ctrl+C and kill
signal.signal(signal.SIGINT, handle_exit)   # Ctrl+C
signal.signal(signal.SIGTERM, handle_exit)  # kill
try:
    signal.signal(signal.SIGTSTP, handle_exit)  # Ctrl+Z
except AttributeError:
    pass

def main():
    print(f"[UEBA Client] Heartbeat producer started for {CLIENT_ID} ...")
    send_heartbeat()

if __name__ == "__main__":
    main()
