# #!/usr/bin/env python3
# import socket
# import json
# from multiprocessing import Process
# import os
# import sys
# import time
# import signal

# # === Load config ===
# CONFIG_PATH = os.environ.get("UEBA_CONFIG", "/home/config.json")
# try:
#     with open(CONFIG_PATH, "r") as f:
#         config = json.load(f)
# except Exception as e:
#     print(f"[Dispatcher] Failed to load config: {e}")
#     sys.exit(1)

# UDP_IP = config["udp"].get("server_ip", "127.0.0.1")
# UDP_PORT = config["udp"].get("server_port", 5000)


# # Internal consumer ports (fixed)
# CONSUMER_PORTS = {
#     "application": 6001,
#     "auth": 6002,
#     "process": 6003,
#     "sru": 6004,
#     "file_sys_monitoring": 6005,
#     "connected_entities": 6006,
#     "login_events": 6007,
# }

# def udp_listener():
#     """Main UDP listener that receives data from producer and fans out."""
#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     try:
#         sock.bind((UDP_IP, UDP_PORT))
#     except OSError as e:
#         print(f"[Dispatcher] Failed to bind {UDP_IP}:{UDP_PORT} -> {e}")
#         sys.exit(1)

#     print(f"[Dispatcher] Listening on {UDP_IP}:{UDP_PORT}")

#     while True:
#         try:
#             data, addr = sock.recvfrom(65535)
#             try:
#                 metrics = json.loads(data.decode("utf-8"))
#                 print(f"[Dispatcher] Received {len(data)} bytes from {addr}")
#                 print(json.dumps(metrics, indent=2))
#             except Exception as e:
#                 print(f"[Dispatcher] JSON decode error from {addr}: {e}")
#                 continue

#             for name, port in CONSUMER_PORTS.items():
#                 try:
#                     sock.sendto(data, (UDP_IP, port))
#                     print(f"[Dispatcher] Forwarded to {name} consumer at {UDP_IP}:{port}")
#                 except Exception as se:
#                     print(f"[Dispatcher] Send error to {name}: {se}")

#         except Exception as e:
#             print(f"[Dispatcher] Socket error: {e}")
#             time.sleep(1)  # prevent tight loop on repeated error


# import threading

# # def main():
# def main(stop_event=None):
#     listener = Process(target=udp_listener)
#     listener.start()
#     print("[Dispatcher] Running... Press Ctrl+C to stop")

#     # Graceful shutdown handler
#     def shutdown(sig, frame):
#         print("\n[Dispatcher] Shutting down...")
#         if listener.is_alive():
#             listener.terminate()
#             listener.join()
#         sys.exit(0)

#     # Only install signal handlers if running in the main thread
#     if threading.current_thread() is threading.main_thread():
#         signal.signal(signal.SIGINT, shutdown)
#         signal.signal(signal.SIGTERM, shutdown)

#     # Keep dispatcher alive without busy loop
#     # while True:
#     while not (stop_event and stop_event.is_set()):
#         time.sleep(1)

#     if listener.is_alive():
#         listener.terminate()
#         listener.join()
#     print("[Dispatcher] Stopped cleanly")
    

# if __name__ == "__main__":
#     main()


#!/usr/bin/env python3
import os, sys, json, socket, time, signal, threading, atexit, fcntl

CONFIG_PATH = os.environ.get("UEBA_CONFIG", "/home/config.json")
try:
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
except Exception as e:
    print(f"[Dispatcher] Failed to load config: {e}")
    sys.exit(1)

UDP_IP   = config.get("udp", {}).get("server_ip", "127.0.0.1")
UDP_PORT = int(config.get("udp", {}).get("server_port", 5000))
if UDP_IP == "127.0.0.0":
    UDP_IP = "127.0.0.1"

CONSUMER_PORTS = {
    "application": 6001,
    "auth": 6002,
    "process": 6003,
    "sru": 6004,
    "file_sys_monitoring": 6005,
    "connected_entities": 6006,
    "login_events": 6007,
}

# show forward confirmations
LOG_FANOUT = True
LOG_PAYLOADS = False   # set True if you want full JSON dumps (noisy)

# single-instance lock
LOCK_PATH = f"/tmp/udp_dispatcher_{UDP_IP.replace('.', '-')}_{UDP_PORT}.lock"
_lock_fd = open(LOCK_PATH, "w")
try:
    fcntl.flock(_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print(f"[Dispatcher] Another udp_dispatcher already bound to {UDP_IP}:{UDP_PORT}. Exiting.")
    sys.exit(1)

@atexit.register
def _cleanup_lock():
    try:
        _lock_fd.close()
        if os.path.exists(LOCK_PATH):
            os.remove(LOCK_PATH)
    except Exception:
        pass

def udp_listener(stop_event: threading.Event):
    # receive socket (exclusive bind)
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # bigger buffers to reduce drops under load
    try:
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    except Exception:
        pass
    try:
        recv_sock.bind((UDP_IP, UDP_PORT))
    except OSError as e:
        print(f"[Dispatcher] Bind failed {UDP_IP}:{UDP_PORT} -> {e}")
        sys.exit(1)
    recv_sock.settimeout(0.5)

    # separate send socket (ephemeral port)
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except Exception:
        pass

    print(f"[Dispatcher] Listening on {UDP_IP}:{UDP_PORT}")

    try:
        while not stop_event.is_set():
            try:
                data, addr = recv_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                if stop_event.is_set():
                    break
                print(f"[Dispatcher] Socket error (recv): {e}")
                time.sleep(0.2)
                continue

            if LOG_PAYLOADS:
                try:
                    obj = json.loads(data.decode("utf-8", errors="ignore"))
                    print(f"[Dispatcher] Received {len(data)} bytes from {addr}")
                    print(json.dumps(obj, indent=2)[:2000])
                except Exception:
                    print(f"[Dispatcher] Received {len(data)} bytes from {addr}")
            else:
                print(f"[Dispatcher] Received {len(data)} bytes from {addr}")

            # fan-out
            for name, port in CONSUMER_PORTS.items():
                try:
                    send_sock.sendto(data, (UDP_IP, port))
                    if LOG_FANOUT:
                        print(f"[Dispatcher] Forwarded -> {name} @ {UDP_IP}:{port}")
                except Exception as se:
                    print(f"[Dispatcher] Send error to {name}@{UDP_IP}:{port} -> {se}")

    finally:
        try: recv_sock.close()
        except Exception: pass
        try: send_sock.close()
        except Exception: pass
        print("[Dispatcher] Stopped cleanly")

def main(stop_event=None):
    local_event = None
    if stop_event is None:
        local_event = threading.Event()
        stop_event = local_event
        def _shut(_sig, _frm):
            print("\n[Dispatcher] Shutting down...")
            stop_event.set()
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT,  _shut)
            signal.signal(signal.SIGTERM, _shut)
    udp_listener(stop_event)
    if local_event is not None:
        time.sleep(0.1)

if __name__ == "__main__":
    main()
