"""
Connected Entities Producer Script
----------------------------------

This script monitors and logs metadata for all peripheral devices connected 
to a user's system as part of a UEBA (User and Entity Behavior Analytics) framework. 
It captures USB devices, Wi-Fi adapters, Bluetooth adapters, internal peripherals 
(keyboard, touchpad, etc.), and connected Bluetooth input devices (e.g., headsets).

Key Features:
- Periodic scanning of USB devices using pyudev
- Detection of Wi-Fi adapters using nmcli
- Discovery of Bluetooth adapters via sysfs
- Parsing of /proc/bus/input/devices to identify internal and Bluetooth input peripherals
- Session tracking with connection/disconnection status and duration
- Sends all device metadata to a Kafka topic (`device-events`) for downstream processing

Dependencies:
- Kafka Python client
- pyudev
- psutil
- nmcli (CLI utility for NetworkManager)
- Linux environment with access to `/proc/bus/input/devices` and `/sys/class/bluetooth`

Usage:
- Automatically starts scanning and streaming on execution
- Intended to run as an agent on Linux endpoints

Author: []
Date: []
"""


import os
import json
import time
import uuid
import socket
import subprocess
from datetime import datetime
import psutil
import pyudev
import re


CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
UDP_PORT = config["udp"]["server_port"]
POLL_INTERVAL = 5   # seconds

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

hostname    = socket.gethostname()
mac_address = ':'.join(f"{(uuid.getnode()>>i)&0xff:02x}" for i in range(40,-1,-8))
username    = psutil.users()[0].name if psutil.users() else "Unknown"

USB_CLASSES = {
    "03": "keyboard/mouse", "02": "communications",
    "08": "mass storage",  "0a": "CDC data",
    "0e": "video",         "0b": "smart card",
    "e0": "wireless",      "ef": "miscellaneous",
    "ff": "vendor specific"
}

def classify_device(dev):
    cls = dev.attributes.get("bDeviceClass")
    if cls and cls.decode() != "00":
        return USB_CLASSES.get(cls.decode(), "unknown")
    cls = dev.attributes.get("bInterfaceClass")
    return USB_CLASSES.get(cls.decode(), "unknown") if cls else "unknown"

def scan_devices():
    ctx = pyudev.Context()
    out = {}
    for dev in ctx.list_devices(subsystem='usb', DEVTYPE='usb_device'):
        vid = dev.attributes.get('idVendor')
        pid = dev.attributes.get('idProduct')
        bus = dev.attributes.get('busnum')
        num = dev.attributes.get('devnum')
        if not (vid and pid and bus and num):
            continue

        uid = f"{vid.decode()}:{pid.decode()}:{bus.decode()}:{num.decode()}"

        # extra properties
        vendor_name   = dev.properties.get('ID_VENDOR')
        product_name  = dev.properties.get('ID_MODEL')
        serial_short  = dev.properties.get('ID_SERIAL_SHORT')
        device_node   = getattr(dev, 'device_node', None)
        sys_name      = dev.sys_name
        driver        = dev.driver
        usb_version   = (dev.attributes.get('bcdUSB') or b"").decode()
        speed         = (dev.attributes.get('speed')  or b"").decode()

        out[uid] = {
            "username":         username,
            "timestamp":        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "hostname":         hostname,
            "mac_address":      mac_address,

            "vendor_id":        vid.decode(),
            "product_id":       pid.decode(),
            "vendor_name":      vendor_name,
            "product_name":     product_name,
            "serial_number":    serial_short,

            "busnum":           bus.decode(),
            "devnum":           num.decode(),
            "device_type":      classify_device(dev),
            "device_node":      device_node,
            "sys_name":         sys_name,
            "driver":           driver,
            "usb_version":      usb_version,
            "speed":            speed,
        }
    return out

# ─── Additional Scanners ────────────────────────────────────────

def scan_wifi_adapters():
    try:
        result = subprocess.run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"], capture_output=True, text=True)
        adapters = []
        for line in result.stdout.strip().split('\n'):
            device, dev_type, state = line.strip().split(':')
            if dev_type == "wifi":
                adapters.append({
                    "device_type": "wifi_adapter",
                    "product_name": device,
                    "connection_status": state
                })
        return adapters
    except Exception as e:
        print(f"[ERROR] Wi-Fi adapter scan failed: {e}")
        return []


def scan_bluetooth_adapters():
    try:
        bt_path = "/sys/class/bluetooth"
        if not os.path.exists(bt_path):
            return []

        adapters = []
        seen = set()

        for dev in os.listdir(bt_path):
            # Skip duplicates like hci0:256 or virtual aliases
            if ':' in dev:
                continue
            if dev in seen:
                continue

            adapters.append({
                "device_type": "bluetooth_adapter",
                "product_name": dev,
                "connection_status": "connected"
            })
            seen.add(dev)

        return adapters

    except Exception as e:
        print(f"[ERROR] Bluetooth adapter scan failed: {e}")
        return []



def scan_internal_input_devices():
    input_path = "/proc/bus/input/devices"
    devices = []
    try:
        with open(input_path, 'r') as f:
            block = ""
            name = "internal_device"
            phys = ""
            for line in f:
                if line.startswith("N: Name="):
                    name = line.strip().split("=", 1)[-1].strip('"')
                elif line.startswith("P: Phys="):
                    phys = line.strip().split("=", 1)[-1].strip()

                if line.strip() == "":
                    # Check for MAC address-like phys (Bluetooth)
                    is_bt_mac = re.match(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$", phys) is not None
                    is_input_type = any(kw in block.lower() for kw in ["keyboard", "mouse", "touchpad"])

                    if is_bt_mac:
                        devices.append({
                            "device_type": "bluetooth_input_device",
                            "product_name": name,
                            "connection_status": "connected"
                        })
                    elif is_input_type and "usb" not in block.lower():
                        devices.append({
                            "device_type": "internal_input",
                            "product_name": name,
                            "connection_status": "connected"
                        })

                    # Reset for next block
                    block = ""
                    name = "internal_device"
                    phys = ""
                else:
                    block += line
        return devices
    except Exception as e:
        print(f"[ERROR] Input device scan failed: {e}")
        return []



# ─── Event Dispatcher ───────────────────────────────────────────

def send_event(meta, status, session_start=None, session_duration=None):
    payload = meta.copy()
    payload.update({
        "topic": "device-events",
        "username": username,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "hostname": hostname,
        "mac_address": mac_address,
        "vendor_id": meta.get("vendor_id", "N/A"),
        "product_id": meta.get("product_id", "N/A"),
        "vendor_name": meta.get("vendor_name", "N/A"),
        "serial_number": meta.get("serial_number", "N/A"),
        "busnum": meta.get("busnum", "N/A"),
        "devnum": meta.get("devnum", "N/A"),
        "device_node": meta.get("device_node", "N/A"),
        "sys_name": meta.get("sys_name", "N/A"),
        "driver": meta.get("driver", "N/A"),
        "usb_version": meta.get("usb_version", "N/A"),
        "speed": meta.get("speed", "N/A"),
        "connection_status": status,
        "session_start_time": session_start,
        "session_duration_sec": session_duration if session_duration is not None else None
    })
    print(f"devices_details: {payload}")
    sock.sendto(json.dumps(payload).encode("utf-8"), (UDP_IP, UDP_PORT))

# ─── Main Loop ──────────────────────────────────────────────────

def main():
    print("\033[1;92m!!!!!!!!! Connected Entities Producer running !!!!!!\033[0m")
    baseline = scan_devices()
    session_map = {}

    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    for uid, meta in baseline.items():
        session_map[uid] = now_str
        send_event(meta, "connected", session_start=now_str)

    # send additional static devices (non-USB)
    for meta in scan_wifi_adapters() + scan_bluetooth_adapters() + scan_internal_input_devices():
        send_event(meta, meta["connection_status"], session_start=now_str)

    while True:
        time.sleep(POLL_INTERVAL)
        current = scan_devices()
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        for uid, meta in current.items():
            if uid not in baseline:
                session_map[uid] = now_str
                send_event(meta, "connected", session_start=now_str)

        for uid, old_meta in baseline.items():
            if uid not in current:
                start_time_str = session_map.get(uid)
                if start_time_str:
                    start_dt = datetime.strptime(start_time_str, '%Y-%m-%d %H:%M:%S')
                    end_dt = datetime.now()
                    duration = int((end_dt - start_dt).total_seconds())
                else:
                    duration = None
                send_event(old_meta, "disconnected", session_start=start_time_str, session_duration=duration)
                if uid in session_map:
                    del session_map[uid]

        baseline = current

if __name__ == "__main__":
    main()
