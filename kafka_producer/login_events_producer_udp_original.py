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
import socket   
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

LOGIN_STATE = {}  # username → login_time
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

shutdown_handled = False  # Global flag (ensure this is at the top with your globals)


def handle_shutdown_signal(signum=None, frame=None):
    global LOGIN_STATE, shutdown_handled
    if shutdown_handled:
        return
    shutdown_handled = True

    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    for username, (login_timestamp, remote_ip, terminal) in LOGIN_STATE.items():
        logout_time = time.time()
        duration = int(logout_time - login_timestamp)
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
            "login_time": datetime.fromtimestamp(login_timestamp).strftime("%Y-%m-%d %H:%M:%S"),
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
            # log(f"[DEBUG] recent_remote_ips: {recent_remote_ips}")

            # Detect new logins
            for username, (login_time, remote_ip, terminal) in current_users.items():
                if username == "testdormantuser":
                    last_login_time = (datetime.now() - timedelta(days=45)).strftime("%Y-%m-%d %H:%M:%S")
                else:
                    last_login_time = get_last_login(username)

                terminal = terminal or ""
                original_ip = remote_ip or "Unknown"
                remote_ip = recent_remote_ips.get(username, original_ip)

                is_remote = remote_ip not in ("", "Unknown", "localhost", "127.0.0.1", "127.0.1.1")
                # print(f"Login... Username: {username}, Terminal: {terminal}, remote_ip: {remote_ip}, is_remote: {is_remote}")
                
                # log(f"[DEBUG] Username: {username}, Terminal: {terminal}, Original IP: {original_ip}, Overridden IP: {remote_ip}")

                if is_remote:
                    auth_type = "ssh"
                elif terminal.startswith("tty"):
                    auth_type = "console"
                elif "seat" in terminal or "login screen" in terminal:
                    auth_type = "gui"
                else:
                    auth_type = "local"

                system_info = get_system_info()
                # geo_info = get_geolocation()
                source_mac = get_mac_address(remote_ip)
                source_hostname = resolve_hostname(remote_ip)

                if username not in LOGIN_STATE:
                    if is_remote:
                        msg = {
                            "topic": "login-events",
                            "event_type": "login",
                            "username": f"{username}",#_{system_info.get('active_mac', '00:00:00:00:00:00')}",
                            "login_time": datetime.fromtimestamp(login_time).strftime("%Y-%m-%d %H:%M:%S"),
                            "last_login_time": last_login_time,
                            "timestamp": now_str,
                            "remote_ip": remote_ip,
                            "auth_type": auth_type,
                            "source_mac": source_mac if source_mac not in ("", "Unknown") else None,
                            "source_hostname": source_hostname if source_hostname not in ("", "Unknown") else None,
                            # "source_os": get_source_os()
                            # **geo_info
                        }
                        msg["source_os"] = get_source_os() 
                        print(f"[22222222DEBUG LOGIN MSG] {json.dumps(msg, indent=2)}")
                    else:
                        msg = {
                            "topic": "login-events",
                            "event_type": "login",
                            # "username": f"{username}_{system_info.get('active_mac', '00:00:00:00:00:00')}",
                            "username": f"{username}",
                            "login_time": datetime.fromtimestamp(login_time).strftime("%Y-%m-%d %H:%M:%S"),
                            "last_login_time": last_login_time,
                            "timestamp": now_str,
                            "remote_ip": remote_ip,
                            "auth_type": auth_type,
                            "source_mac": source_mac if source_mac not in ("", "Unknown") else None,
                            "source_hostname": source_hostname if source_hostname not in ("", "Unknown") else None,
                            **system_info,
                            # **geo_info,
                            # "source_os": get_source_os()
                        }
                        msg["source_os"] = get_source_os() 
                        print(f"[LOGIN MSG] {json.dumps(msg, indent=2)}")

                    # producer.send(KAFKA_TOPIC, value=msg)
                    sock.sendto(json.dumps(msg).encode("utf-8"), (UDP_IP, UDP_PORT))

                    # log(f" Sent login event: {msg}")

            # Detect logouts
            for username, (login_timestamp, remote_ip, terminal) in LOGIN_STATE.items():
                if username not in current_users:
                    logout_time = time.time()
                    duration = int(logout_time - login_timestamp)

                    terminal = terminal or ""
                    original_ip = remote_ip or "Unknown"
                    remote_ip = recent_remote_ips.get(username, original_ip)

                    is_remote = remote_ip not in ("", "Unknown", "localhost", "127.0.0.1", "127.0.1.1")
                    print(f"Logout...[DEBUG][AUTH_TYPE] Username: {username}, Terminal: {terminal}, remote_ip: {remote_ip}, is_remote: {is_remote}")

                    if is_remote:
                        auth_type = "ssh"
                    elif terminal.startswith("tty"):
                        auth_type = "console"
                    elif "seat" in terminal or "login screen" in terminal:
                        auth_type = "gui"
                    else:
                        auth_type = "local"

                    system_info = get_system_info()
                    # geo_info = get_geolocation()
                    source_mac = get_mac_address(remote_ip)
                    source_hostname = resolve_hostname(remote_ip)

                    if is_remote:
                        msg = {
                            "topic": "login-events",
                            "event_type": "logout",
                            "username": f"{username}",#_{system_info.get('active_mac', '00:00:00:00:00:00')}",
                            "login_time": datetime.fromtimestamp(login_timestamp).strftime("%Y-%m-%d %H:%M:%S"),
                            "logout_time": datetime.fromtimestamp(logout_time).strftime("%Y-%m-%d %H:%M:%S"),
                            "session_duration_seconds": duration,
                            "timestamp": now_str,
                            "remote_ip": remote_ip,
                            "auth_type": auth_type,
                            "source_mac": source_mac if source_mac not in ("", "Unknown") else None,
                            "source_hostname": source_hostname if source_hostname not in ("", "Unknown") else None,
                            # "source_os": get_source_os(),
                            # **geo_info
                        }
                        msg["source_os"] = get_source_os() 
                        print(f"[44444444444DEBUG LOGIN MSG] {json.dumps(msg, indent=2)}")
                    else:
                        msg = {
                            "topic": "login-events",
                            "event_type": "logout",
                            # "username": f"{username}_{system_info.get('active_mac', '00:00:00:00:00:00')}",
                            "username": f"{username}",
                            "login_time": datetime.fromtimestamp(login_timestamp).strftime("%Y-%m-%d %H:%M:%S"),
                            "logout_time": datetime.fromtimestamp(logout_time).strftime("%Y-%m-%d %H:%M:%S"),
                            "session_duration_seconds": duration,
                            "timestamp": now_str,
                            "remote_ip": remote_ip,
                            "auth_type": auth_type,
                            "source_mac": source_mac if source_mac not in ("", "Unknown") else None,
                            "source_hostname": source_hostname if source_hostname not in ("", "Unknown") else None,
                            **system_info,
                            # **geo_info,
                            # "source_os": get_source_os()
                        }
                        msg["source_os"] = get_source_os() 
                        print(f"[5555555555DEBUG LOGIN MSG] {json.dumps(msg, indent=2)}")
                    # producer.send(KAFKA_TOPIC, value=msg)
                    sock.sendto(json.dumps(msg).encode("utf-8"), (UDP_IP, UDP_PORT))

                    # log(f" Sent logout event: {msg}")

            # Update login state
            LOGIN_STATE = current_users
            time.sleep(SCAN_INTERVAL)

        except KeyboardInterrupt:
            log(" Stopped by user")
            break
        except Exception as e:
            log(f"[ERROR] {e}")
            time.sleep(5)



# def send_test_events():
#     # Test case 1: Only triggers raw_analysis_log (risk score 3)
#     msg_raw_only = {
#         "event_type": "login",
#         "username": "testuser2",
#         "login_time": "2024-06-27 14:00:00",        # 2pm, outside 8–13
#         "logout_time": "2024-06-27 17:00:00",
#         "session_duration_seconds": 10800,          # 3 hours (normal)
#         "timestamp": "2024-06-27 14:00:00",
#         "remote_ip": "192.168.1.25",                # Normal IP (allowed)
#         "auth_type": "local",
#         "mac_address": "00:11:22:33:44:55",
#         "hostname": "test-host",
#     }
#     producer.send(KAFKA_TOPIC, value=msg_raw_only)
#     # log(f"[TEST] Sent test event (raw only): {msg_raw_only}")
#     time.sleep(1)

#     # Test case 2: Triggers both raw_analysis_log and anomalies_log (risk score 8)
#     msg_raw_and_anomaly = {
#         "event_type": "login",
#         "username": "testuser2",
#         "login_time": "2024-06-27 14:00:00",        # 2pm, outside 8–13
#         "logout_time": "2024-06-27 15:00:00",
#         "session_duration_seconds": 3600,           # 1 hour (unusual)
#         "timestamp": "2024-06-27 14:00:00",
#         "remote_ip": "10.10.10.50",                 # Not in allowed range
#         "auth_type": "local",
#         "mac_address": "00:11:22:33:44:55",
#         "hostname": "test-host",
#     }
#     producer.send(KAFKA_TOPIC, value=msg_raw_and_anomaly)
#     # log(f"[TEST] Sent test event (raw + anomaly): {msg_raw_and_anomaly}")
#     time.sleep(1)




if __name__ == "__main__":
    # send_test_events() 
    # threading.Thread(target=monitor_su_logins, daemon=True).start()
    # Register shutdown signal handlers
    signal.signal(signal.SIGTERM, handle_shutdown_signal)
    signal.signal(signal.SIGINT, handle_shutdown_signal)  # for Ctrl+C

    # Optional: also register for clean exit when script ends
    atexit.register(handle_shutdown_signal, None, None)

    main()
