
import os
import sys
import json
import socket
import threading
import signal
import time

import subprocess
import re



# Add path for local imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# === Load Config ===
CONFIG_PATH = "/home/config.json"
# CONFIG_PATH = "/home/ueba_config.json"
try:
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
except Exception as e:
    print(f"[UEBA Client] Failed to load config: {e}")
    sys.exit(1)

UDP_IP = config["udp"]["server_ip"]
UDP_PORT = config["udp"]["server_port"]


# print(f"[UEBA Client] Loaded config. Sending via UDP {UDP_IP}:{UDP_PORT}")

# === Import Producers ===
from kafka_producer.connected_entities_producer_udp import main as connected_entities_main
from kafka_producer.file_sys_monitoring_producer_udp_old import main as file_sys_main
from kafka_producer.login_events_producer_udp import main as login_events_main
from kafka_producer.system_monitor_producer_udp import main as system_monitor_main

from kafka_producer.privilege_user_monitoring_producer_udp import main as privileged_user_monitoring_main


## Added by simar
from kafka_producer.login_events_producer_udp import handle_shutdown_signal 
from kafka_producer.clients_heartbeat_producer_udp import send_heartbeat # on 19th septemeber
from kafka_producer.clients_heartbeat_producer_udp import send_shutdown # on 25th septemeber

from kafka_producer.clients_heartbeat_producer_udp import main as heartbeat_main



# === Thread Wrapper ===
def run_producer(name, target):
    try:
        print(f"[UEBA Client] Starting {name} ...")
        target()
    except Exception as e:
        print(f"[UEBA Client] {name} crashed: {e}")

# === Signal Handling ===
stop_event = threading.Event()
shutdown_requested = threading.Event()




def handle_exit(signum, frame):
    stop_event.set()            # stop producers
    shutdown_requested.set()    # request shutdown

# def perform_shutdown():
#     print("\n[UEBA Client] Shutting down all producers...")
#     stop_event.set()

#     try:
#         handle_shutdown_signal(exit_after=False)
#     except Exception as e:
#         print(f"[UEBA Client] Failed to flush login_events logout: {e}")

#     try:
#         send_shutdown()
#     except Exception as e:
#         print(f"[UEBA Client] Failed to send shutdown heartbeat: {e}")

#     time.sleep(1)  # let UDP packets flush
#     os._exit(0)

def perform_shutdown():
    if shutdown_requested.is_set():
        # Prevent repeated shutdown attempts
        shutdown_requested.clear()

    print("\n[UEBA Client] Shutting down all producers...")
    stop_event.set()

    # ========= LOCAL LOGOUT CONFIRMATION ==========
    try:
        with open("/var/log/ueba_logout_test.log", "a") as f:
            f.write(f"Logout event triggered at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    except Exception as e:
        print(f"[UEBA Client] Failed to write logout log: {e}")

    # ========= SEND REAL LOGOUT + INACTIVE HEARTBEAT ==========
    try:
        handle_shutdown_signal(exit_after=False)
    except Exception as e:
        print(f"[UEBA Client] Failed to flush login_events logout: {e}")

    try:
        send_shutdown()
    except Exception as e:
        print(f"[UEBA Client] Failed to send shutdown heartbeat: {e}")

    # ========= EXIT CLEANLY ==========
    time.sleep(1)
    os._exit(0)



# Trap Ctrl+C and kill
signal.signal(signal.SIGINT, handle_exit)   # Ctrl+C
signal.signal(signal.SIGTERM, handle_exit)  # kill

# Optional: Trap Ctrl+Z (suspend) to also exit
try:
    signal.signal(signal.SIGTSTP, handle_exit)  # Ctrl+Z
except AttributeError:
    # SIGTSTP may not exist on Windows
    pass

import psutil
import subprocess
import re
import threading

def get_active_usernames():
    """
    Returns a set of currently logged-in usernames.
    """
    return {u.name for u in psutil.users()}


# # SAFE PATTERNS – no PAM noise, no sudo noise
# LOGOUT_PATTERNS = [
#     r"session closed for user",        # systemd-logind genuine logout
#     r"systemd-logind.*logged out",
# ]
# SAFE PATTERNS – no PAM noise, no sudo noise
LOGOUT_PATTERNS = [
    r"systemd-logind.*logged out"
]


def watch_logout_events():

    cmd = ["journalctl", "-f", "--since=now", "-o", "short"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    while True:
        line = proc.stdout.readline()
        if not line:
            continue

        low = line.lower()

        # Check if log line resembles an actual logout event
        if not any(re.search(p, low) for p in LOGOUT_PATTERNS):
            continue

        # Get currently logged-in users dynamically
        active_users = get_active_usernames()

        # Check if the logout line contains ANY active user's name
        for user in active_users:
            # Ensure username match is exact (avoid substrings)
            if re.search(rf"\b{re.escape(user.lower())}\b", low):
                print(f"[UEBA] Valid logout detected via journalctl for user: {user}")
                shutdown_requested.set()
                return



# === Main Launcher ===
# def main():
#     threads = []
#     producers = {
#         "ConnectedEntitiesProducer": connected_entities_main,
#         "FileSystemMonitoringProducer": file_sys_main,
#         "LoginEventsProducer": login_events_main,
#         "SystemMonitorProducer": system_monitor_main,
#         # "HeartbeatProducer": send_heartbeat,
#         "HeartbeatProducer": lambda: send_heartbeat(stop_event),
#         "PrivilegedUserMonitoringProducer": privileged_user_monitoring_main,
#     }

#     for name, func in producers.items():
#         # t = threading.Thread(target=run_producer, args=(name, func), daemon=True)  # 27 nov
#         t = threading.Thread(target=run_producer, args=(name, func), daemon=False)

#         threads.append(t)
#         t.start()

#     print("[UEBA Client] All producers started.")

#     try:
#         # while not stop_event.is_set():
#         #     time.sleep(1)
#         # while not stop_event.is_set():
#         #     time.sleep(1)
#         #     if shutdown_requested.is_set():
#         #         perform_shutdown()
#         while True:
#             time.sleep(1)
#             if shutdown_requested.is_set():
#                 perform_shutdown()

#     except KeyboardInterrupt:
#         handle_exit(None, None)

def main():
    threads = []
    producers = {
        "ConnectedEntitiesProducer": connected_entities_main,
        "FileSystemMonitoringProducer": file_sys_main,
        "LoginEventsProducer": login_events_main,
        "SystemMonitorProducer": system_monitor_main,
        # "HeartbeatProducer": lambda: send_heartbeat(stop_event),
        "HeartbeatProducer": heartbeat_main,
        "PrivilegedUserMonitoringProducer": privileged_user_monitoring_main,
    }

    for name, func in producers.items():
        t = threading.Thread(target=run_producer, args=(name, func), daemon=False)
        threads.append(t)
        t.start()

    print("[UEBA Client] All producers started.")

    logout_thread = threading.Thread(target=watch_logout_events, daemon=True)
    logout_thread.start()

    try:
        while True:
            time.sleep(1)
            if shutdown_requested.is_set():
                perform_shutdown()
                return

    except KeyboardInterrupt:
        handle_exit(None, None)



if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--shutdown",
        action="store_true",
        help="Send logout + inactive heartbeat and exit"
    )
    args = parser.parse_args()

    if args.shutdown:
        try:
            handle_shutdown_signal(exit_after=False)
        except Exception as e:
            print(f"[UEBA Client] Failed to flush login_events logout: {e}")

        try:
            send_shutdown()
        except Exception as e:
            print(f"[UEBA Client] Failed to send shutdown heartbeat: {e}")

        sys.exit(0)
    else:
        main()

