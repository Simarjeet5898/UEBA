"""
User Session Tracking Producer Script
-------------------------------------

This script monitors and logs user session activity on an endpoint system 
(Linux) as part of a UEBA (User and Entity Behavior Analytics) framework. 
It captures detailed login and logout events, including timestamps, IP 
address, session duration, and contextual metadata (host, MAC, geolocation).

Key Features:
- Tracks user login and logout times using psutil and system logs
- Calculates session duration automatically
- Detects local, GUI, SSH, and console login types
- Extracts geolocation info via public IP APIs
- Resolves remote hostnames and MAC addresses (for remote logins)
- Streams session metadata to a Kafka topic (`login-events`) for downstream analysis

Dependencies:
- Kafka Python client
- psutil
- requests
- subprocess, re, socket
- External: `last` command, internet access for IP geolocation

Usage:
- Automatically starts monitoring and sending session events on execution
- Designed to run continuously as a background agent on Linux endpoints

Author: []
Date: []
"""

import time
import json
import socket
import uuid
import psutil
import platform
from datetime import datetime,timedelta
# from kafka import KafkaProducer 
import subprocess
import re
import requests
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from kafka_producer.new_log_monitor import get_recent_remote_logins, get_mac_address, resolve_hostname
import threading
import select
from collections import defaultdict
import signal
import atexit


###################UEBA_1:: User Session Tracking########################





# === Configuration ===
CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
UDP_PORT = config["udp"]["server_port"]
SCAN_INTERVAL = 5  # seconds

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def normalize_ip(ip):
    if not ip or ip in ("Unknown", "localhost", "127.0.0.1", "127.0.1.1"):
        return "127.0.0.1"
    return ip.strip()

def normalize_terminal(term):
    if not term:
        return ""
    if term.startswith("pts/"):
        return "pts"   # collapse pts/0, pts/1, etc.
    return term.strip()

def make_session_key(username, terminal, remote_ip):
    return (
        username,
        normalize_terminal(terminal),
        normalize_ip(remote_ip)
    )


def get_public_ip():
    try:
        resp = requests.get("https://api.ipify.org", timeout=2)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception:
        pass
    return "Unknown"

def get_geolocation():
    ip = get_public_ip()
    if ip == "Unknown":
        return {
            "public_ip": "Unknown",
            "geo_country": "Unknown",
            "geo_region": "Unknown",
            "geo_city": "Unknown"
        }
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "public_ip": ip,
                "geo_country": data.get("country", "Unknown"),
                "geo_region": data.get("regionName", "Unknown"),
                "geo_city": data.get("city", "Unknown")
            }
    except Exception:
        pass
    return {
        "public_ip": ip,
        "geo_country": "Unknown",
        "geo_region": "Unknown",
        "geo_city": "Unknown"
    }

# LOGIN_STATE = {}  # username → login_time
# (username, terminal, resolved_remote_ip) -> started_epoch
LOGIN_STATE = {}

# GEO_INFO = get_geolocation()


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def get_system_info():
    interfaces = psutil.net_if_addrs()
    macs = []
    active_mac = None
    lan_ip = None

    for iface, addrs in interfaces.items():
        mac = None
        ip = None

        for addr in addrs:
            if addr.family == psutil.AF_LINK:
                mac = addr.address
            elif addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ip = addr.address

        if mac and mac != '00:00:00:00:00:00':
            macs.append(mac)
            if ip and not lan_ip:
                lan_ip = ip
                active_mac = mac

    return {
        "hostname": socket.gethostname(),
        "mac_addresses": macs,
        "active_mac": active_mac or "00:00:00:00:00:00",
        "lan_ip": lan_ip or "Unknown",
        "source_os": f"{platform.system()} {platform.release()}"
        
        # "os": platform.system(),
        # "auth_type": "local"
        
    }



# producer = KafkaProducer(
#     bootstrap_servers=BOOTSTRAP_SERVER,
#     value_serializer=lambda v: json.dumps(v).encode("utf-8"),
#     acks='all'
# )


# def get_current_users():
#     return {user.name: user.started for user in psutil.users()}

def get_source_os():
    system_name = platform.system()
    return system_name if system_name else "Unknown"


def get_current_users():
    users = {}
    for user in psutil.users():
        username = user.name
        started = user.started
        host = user.host or "Unknown"
        if host == "localhost":
            try:
                host = socket.gethostbyname(socket.gethostname())
            except:
                host = "127.0.0.1"
        users[username] = (started, host, user.terminal)
    return users


def get_last_login(username):
    try:
        result = subprocess.run(["last", "-F", "-n", "100"], capture_output=True, text=True, timeout=1)
        for line in result.stdout.splitlines():
            if " - " in line:
                if line.split()[0] == username[:8]:
                    match = re.search(r"\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}", line)
                    if match:
                        dt_str = match.group(0)
                        return datetime.strptime(dt_str, "%a %b %d %H:%M:%S %Y").strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return None

def get_current_login_from_last(username, terminal):
    """
    Return '%Y-%m-%d %H:%M:%S' for the user's current 'still logged in' start time from `last -F`.
    Ignores terminal filtering to avoid seat0/login screen/:0 mismatches.
    """
    try:
        out = subprocess.run(["last", "-F", "-n", "200", username],
                             capture_output=True, text=True, timeout=2).stdout
        for line in out.splitlines():
            if "still logged in" not in line:
                continue
            # e.g. "simar  tty2  tty2  Thu Sep  4 10:31:51 2025   still logged in"
            m = re.search(r"\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}", line)
            if m:
                dt = datetime.strptime(m.group(0), "%a %b %d %H:%M:%S %Y")
                return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return None



shutdown_handled = False  # Global flag (ensure this is at the top with your globals)


def handle_shutdown_signal(signum=None, frame=None):
    global LOGIN_STATE, shutdown_handled
    if shutdown_handled:
        return
    shutdown_handled = True

    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    for (username, terminal, remote_ip), started_epoch in LOGIN_STATE.items():
        logout_time = time.time()
        duration = int(logout_time - started_epoch)
        last_login_time = get_last_login(username)

        is_remote = remote_ip not in ("", "Unknown", "localhost", "127.0.0.1", "127.0.1.1")
        auth_type = "ssh" if is_remote else "local"

        system_info = get_system_info()
        # geo_info = get_geolocation()
        source_mac = get_mac_address(remote_ip)
        source_hostname = resolve_hostname(remote_ip)

        msg = {
            "topic": "login-events",
            "event_type": "logout",
            "username": username,
            "login_time": datetime.fromtimestamp(started_epoch).strftime("%Y-%m-%d %H:%M:%S"),
            "logout_time": now_str,
            "last_login_time": last_login_time,
            "session_duration_seconds": duration,
            "timestamp": now_str,
            "remote_ip": remote_ip,
            "auth_type": auth_type,
            "source_mac": source_mac if source_mac not in ("", "Unknown") else None,
            "source_hostname": source_hostname if source_hostname not in ("", "Unknown") else None,
            **system_info,
            # **geo_info,
        }

        msg["source_os"] = get_source_os()
        print(f"[DEBUG LOGOUT MSG] {json.dumps(msg, indent=2)}")

        # send via UDP instead of Kafka
        sock.sendto(json.dumps(msg).encode("utf-8"), (UDP_IP, UDP_PORT))

    sys.exit(0)




def main():
    global LOGIN_STATE
    print("\033[1;32m  !!!!!Login Events Producer started!!!!!!\033[0m")

    while True:
        try:
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            current_users = get_current_users()
            recent_remote_ips = get_recent_remote_logins()

            for username, (started_epoch, remote_ip, terminal) in current_users.items():
                terminal = terminal or ""
                original_ip = remote_ip or "Unknown"
                remote_ip = recent_remote_ips.get(username, original_ip)

                is_remote = remote_ip not in ("", "Unknown", "localhost", "127.0.0.1", "127.0.1.1")
                if is_remote:
                    auth_type = "ssh"
                elif terminal.startswith("tty"):
                    auth_type = "console"
                elif "seat" in terminal or "login screen" in terminal:
                    auth_type = "gui"
                else:
                    auth_type = "local"

                # session identity (prevents collisions across tty/seat/ip)
                # session_key = (username, terminal, remote_ip or "")
                session_key = make_session_key(username, terminal, remote_ip)


                # last_login_time logic stays as-is
                if username == "testdormantuser":
                    last_login_time = (datetime.now() - timedelta(days=45)).strftime("%Y-%m-%d %H:%M:%S")
                else:
                    last_login_time = get_last_login(username)

                # prefer wtmp/`last` start time for ITP parity; fallback to psutil.started
                login_time_str = get_current_login_from_last(username, terminal)
                if not login_time_str:
                    login_time_str = datetime.fromtimestamp(started_epoch).strftime("%Y-%m-%d %H:%M:%S")

                if session_key not in LOGIN_STATE:
                    system_info = get_system_info()
                    source_mac = get_mac_address(remote_ip)
                    source_hostname = resolve_hostname(remote_ip)

                    msg = {
                        "topic": "login-events",
                        "event_type": "login",
                        "username": username,
                        "login_time": login_time_str,
                        "last_login_time": last_login_time,
                        "timestamp": now_str,
                        "remote_ip": remote_ip,
                        "auth_type": auth_type,
                        "source_mac": source_mac if source_mac not in ("", "Unknown") else None,
                        "source_hostname": source_hostname if source_hostname not in ("", "Unknown") else None,
                        **system_info,
                    }
                    msg["source_os"] = get_source_os()
                    print(f"[LOGIN MSG] {json.dumps(msg, indent=2)}")
                    sock.sendto(json.dumps(msg).encode("utf-8"), (UDP_IP, UDP_PORT))


                    # log(f" Sent login event: {msg}")
                    
            current_keys = set()
            for u, (st, rip, term) in current_users.items():
                cur_ip = recent_remote_ips.get(u, rip or "Unknown")
                # current_keys.add((u, term or "", cur_ip or ""))
                current_keys.add(make_session_key(u, term, cur_ip))


            # Detect logouts per session_key
            for (u, t, r), started_epoch in list(LOGIN_STATE.items()):
                if (u, t, r) not in current_keys:
                    logout_time = time.time()
                    duration = int(logout_time - started_epoch)

                    terminal = t or ""
                    remote_ip = r or "Unknown"
                    is_remote = remote_ip not in ("", "Unknown", "localhost", "127.0.0.1", "127.0.1.1")
                    if is_remote:
                        auth_type = "ssh"
                    elif terminal.startswith("tty"):
                        auth_type = "console"
                    elif "seat" in terminal or "login screen" in terminal:
                        auth_type = "gui"
                    else:
                        auth_type = "local"

                    system_info = get_system_info()
                    source_mac = get_mac_address(remote_ip)
                    source_hostname = resolve_hostname(remote_ip)

                    msg = {
                        "topic": "login-events",
                        "event_type": "logout",
                        "username": u,
                        "login_time": datetime.fromtimestamp(started_epoch).strftime("%Y-%m-%d %H:%M:%S"),
                        "logout_time": datetime.fromtimestamp(logout_time).strftime("%Y-%m-%d %H:%M:%S"),
                        "session_duration_seconds": duration,
                        "timestamp": now_str,
                        "remote_ip": remote_ip,
                        "auth_type": auth_type,
                        "source_mac": source_mac if source_mac not in ("", "Unknown") else None,
                        "source_hostname": source_hostname if source_hostname not in ("", "Unknown") else None,
                        **system_info,
                    }
                    msg["source_os"] = get_source_os()
                    print(f"[LOGOUT MSG] {json.dumps(msg, indent=2)}")
                    sock.sendto(json.dumps(msg).encode("utf-8"), (UDP_IP, UDP_PORT))


                    # log(f" Sent logout event: {msg}")

            # Update login state
            # LOGIN_STATE = current_users
            LOGIN_STATE = {}
            for u, (st, rip, term) in current_users.items():
                cur_ip = recent_remote_ips.get(u, rip or "Unknown")
                # LOGIN_STATE[(u, term or "", cur_ip or "")] = st
                LOGIN_STATE[make_session_key(u, term, cur_ip)] = st

            time.sleep(SCAN_INTERVAL)

        except KeyboardInterrupt:
            log(" Stopped by user")
            break
        except Exception as e:
            log(f"[ERROR] {e}")
            time.sleep(5)



def send_test_events():
    # === same UDP setup as main producer ===
    CONFIG_PATH = "/home/config.json"
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)

    UDP_IP = config["udp"]["server_ip"]
    UDP_PORT = config["udp"]["server_port"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Test case 1: Normal (should NOT raise anomaly)
    msg_raw_only = {
        "topic": "login-events",
        "event_type": "login",
        "username": "testuser2",
        "login_time": "2024-06-27 14:00:00",   # 2 PM
        "logout_time": "2024-06-27 17:00:00",
        "session_duration_seconds": 10800,     # 3 hours
        "timestamp": "2024-06-27 14:00:00",
        "remote_ip": "192.168.1.25",           # Allowed IP
        "auth_type": "local",
        "mac_address": "00:11:22:33:44:55",
        "hostname": "test-host",
    }
    sock.sendto(json.dumps(msg_raw_only).encode("utf-8"), (UDP_IP, UDP_PORT))
    print(f"[TEST] Sent raw-only test event → {msg_raw_only}")
    time.sleep(1)

    # Test case 2: Anomaly (IP not allowed + short session)
    msg_raw_and_anomaly = {
        "topic": "login-events",
        "event_type": "login",
        "username": "testuser2",
        "login_time": "2024-06-27 14:00:00",   # 2 PM
        "logout_time": "2024-06-27 15:00:00",
        "session_duration_seconds": 3600,      # 1 hour
        "timestamp": "2024-06-27 14:00:00",
        "remote_ip": "10.10.10.50",            # Not allowed
        "auth_type": "local",
        "mac_address": "00:11:22:33:44:55",
        "hostname": "test-host",
    }
    sock.sendto(json.dumps(msg_raw_and_anomaly).encode("utf-8"), (UDP_IP, UDP_PORT))
    print(f"[TEST] Sent anomaly test event → {msg_raw_and_anomaly}")
    time.sleep(1)

def send_pattern_events():
    # === same UDP setup as main producer ===
    CONFIG_PATH = "/home/config.json"
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)

    UDP_IP = config["udp"]["server_ip"]
    UDP_PORT = config["udp"]["server_port"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Send 5–10 normal events (inside baseline window, allowed IP, normal duration)
    for i in range(10):
        msg_normal = {
            "topic": "login-events",
            "event_type": "login",
            "username": "testuser2",
            "login_time": f"2024-06-27 10:00:00",   # 10 AM (inside baseline)
            "logout_time": f"2024-06-27 18:00:00",  # 8 hrs session
            "session_duration_seconds": 28800,      # 8 hours
            "timestamp": f"2024-06-27 10:00:00",
            "remote_ip": "192.168.1.25",            # Allowed IP
            "auth_type": "local",
            "mac_address": "00:11:22:33:44:55",
            "hostname": "test-host",
        }
        sock.sendto(json.dumps(msg_normal).encode("utf-8"), (UDP_IP, UDP_PORT))
        print(f"[TEST] Sent normal test event {i+1} → {msg_normal}")
        time.sleep(1)



if __name__ == "__main__":
    # send_test_events()
    # send_pattern_events ()
    # threading.Thread(target=monitor_su_logins, daemon=True).start()
    # Register shutdown signal handlers
    signal.signal(signal.SIGTERM, handle_shutdown_signal)
    signal.signal(signal.SIGINT, handle_shutdown_signal)  # for Ctrl+C

    # Optional: also register for clean exit when script ends
    atexit.register(handle_shutdown_signal, None, None)

    main()
