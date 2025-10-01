
import os
import sys
import json
import socket
import threading
import signal
import time

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

print(f"[UEBA Client] Loaded config. Sending via UDP {UDP_IP}:{UDP_PORT}")

# === Import Producers ===
from kafka_producer.connected_entities_producer_udp import main as connected_entities_main
from kafka_producer.file_sys_monitoring_producer_udp import main as file_sys_main
from kafka_producer.login_events_producer_udp import main as login_events_main
from kafka_producer.system_monitor_producer_udp import main as system_monitor_main


## Added by simar
from kafka_producer.login_events_producer_udp import handle_shutdown_signal 
from kafka_producer.clients_heartbeat_producer_udp import send_heartbeat # on 19th septemeber
from kafka_producer.clients_heartbeat_producer_udp import send_shutdown # on 25th septemeber


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


# def handle_exit(signum, frame):
#     print("\n[UEBA Client] Shutting down all producers...")
#     stop_event.set()
#     sys.exit(0)


# def handle_exit(signum, frame):
#     print("\n[UEBA Client] Shutting down all producers...")
#     stop_event.set()   # add this line

#     # Send logout event
#     try:
#         handle_shutdown_signal(exit_after=False)
#     except Exception as e:
#         print(f"[UEBA Client] Failed to flush login_events logout: {e}")

#     # Send inactive heartbeat
#     try:
#         send_shutdown()
#     except Exception as e:
#         print(f"[UEBA Client] Failed to send shutdown heartbeat: {e}")

#     # Give a moment for UDP packets to leave before hard exit
#     time.sleep(1)
#     os._exit(0)

# def handle_exit(signum, frame):
#     # only mark shutdown, no heavy work inside signal handler
#     shutdown_requested.set()

def handle_exit(signum, frame):
    stop_event.set()            # stop producers
    shutdown_requested.set()    # request shutdown

def perform_shutdown():
    print("\n[UEBA Client] Shutting down all producers...")
    stop_event.set()

    try:
        handle_shutdown_signal(exit_after=False)
    except Exception as e:
        print(f"[UEBA Client] Failed to flush login_events logout: {e}")

    try:
        send_shutdown()
    except Exception as e:
        print(f"[UEBA Client] Failed to send shutdown heartbeat: {e}")

    time.sleep(1)  # let UDP packets flush
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

# === Main Launcher ===
def main():
    threads = []
    producers = {
        "ConnectedEntitiesProducer": connected_entities_main,
        "FileSystemMonitoringProducer": file_sys_main,
        "LoginEventsProducer": login_events_main,
        "SystemMonitorProducer": system_monitor_main,
        # "HeartbeatProducer": send_heartbeat,
        "HeartbeatProducer": lambda: send_heartbeat(stop_event),
    }

    for name, func in producers.items():
        t = threading.Thread(target=run_producer, args=(name, func), daemon=True)
        threads.append(t)
        t.start()

    print("[UEBA Client] All producers started.")

    try:
        # while not stop_event.is_set():
        #     time.sleep(1)
        while not stop_event.is_set():
            time.sleep(1)
            if shutdown_requested.is_set():
                perform_shutdown()
    except KeyboardInterrupt:
        handle_exit(None, None)

# if __name__ == "__main__":
#     main()
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

