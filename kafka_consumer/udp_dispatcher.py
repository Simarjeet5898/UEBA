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
# if UDP_IP == "127.0.0.0":
if UDP_IP in ("127.0.0.0", "0.0.0.0"):
    UDP_IP = "127.0.0.1"

ACK_PORT = int(config.get("buffering", {}).get("ack_port", 7010))

ACK_ENABLED = bool(config.get("buffering", {}).get("enabled", False))
print(f"[Dispatcher] ACK_ENABLED={ACK_ENABLED} ACK_PORT={ACK_PORT} CONFIG_PATH={CONFIG_PATH}")


CONSUMER_PORTS = {
    "application": 6001,
    "auth": 6002,
    "process": 6003,
    "sru": 6004,
    "file_sys_monitoring": 6005,
    "connected_entities": 6006,
    "login_events": 6007,
    "clients_heartbeat": 6008, 
    "privileged_user_monitoring": 6009,
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

# def udp_listener(stop_event: threading.Event):
#     # receive socket (exclusive bind)
#     recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     # bigger buffers to reduce drops under load
#     try:
#         recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
#     except Exception:
#         pass
#     try:
#         recv_sock.bind((UDP_IP, UDP_PORT))
#     except OSError as e:
#         print(f"[Dispatcher] Bind failed {UDP_IP}:{UDP_PORT} -> {e}")
#         sys.exit(1)
#     recv_sock.settimeout(0.5)

#     # separate send socket (ephemeral port)
#     send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     try:
#         send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
#     except Exception:
#         pass

#     # print(f"[Dispatcher] Listening on {UDP_IP}:{UDP_PORT}")
#     print(f"\033[91m[Dispatcher] Listening on {UDP_IP}:{UDP_PORT}\033[0m")


#     try:
#         while not stop_event.is_set():
#             try:
#                 data, addr = recv_sock.recvfrom(65535)
#                 # print(f"[Dispatcher][DEBUG] recvfrom addr={addr} bytes={len(data)}")
#                 print("[Dispatcher][CHECK] first50 =", data[:50])
#                 print(f"[Dispatcher][DEBUG] recvfrom addr={addr} bytes={len(data)}")

#             except socket.timeout:
#                 continue
#             except OSError as e:
#                 if stop_event.is_set():
#                     break
#                 print(f"[Dispatcher] Socket error (recv): {e}")
#                 time.sleep(0.2)
#                 continue

#             if LOG_PAYLOADS:
#                 try:
#                     obj = json.loads(data.decode("utf-8", errors="ignore"))
#                     # print(f"[Dispatcher] Received {len(data)} bytes from {addr}")
#                     # print(json.dumps(obj, indent=2)[:2000])
#                 except Exception:
#                     print(f"[Dispatcher] Received {len(data)} bytes from {addr}")
#             else:
#                 print(f"[Dispatcher] Received {len(data)} bytes from {addr}")

#             # ---- BUFFER UNWRAP + ACK (single place, avoids changing all consumers) ----
#             data_to_forward = data

#             if ACK_ENABLED:
#                 try:
#                     obj = json.loads(data.decode("utf-8", errors="ignore"))
#                     # print("[Dispatcher][DEBUG] decoded obj =", obj)

#                     if isinstance(obj, dict) and obj.get("type") == "buffered_event":
#                         msg_id = obj.get("msg_id")
#                         print(f"[Dispatcher] buffered_event detected from {addr}, msg_id={msg_id}")


#                         # 1) Send ACK back to client (client listens on ACK_PORT)
#                         if msg_id:
#                             ack_msg = {"type": "ack", "msg_id": msg_id}
#                             try:
#                                 # print(f"[Dispatcher] Sending ACK msg_id={msg_id} to {addr[0]}:{ACK_PORT}")
#                                 print(f"[Dispatcher][DEBUG] ACK about to send: msg_id={msg_id} recv_addr={addr} ack_dest=({addr[0]},{ACK_PORT})")

#                                 send_sock.sendto(
#                                     json.dumps(ack_msg).encode("utf-8"),
#                                     (addr[0], ACK_PORT)
#                                     # addr
#                                 )
#                                 print(f"[Dispatcher][DEBUG] ACK sendto OK msg_id={msg_id} dest={addr}")
                            
#                             except Exception as ae:
#                                 print(f"[Dispatcher] ACK send failed to {addr[0]}:{ACK_PORT} -> {ae}")

#                         # 2) Unwrap and forward only the original payload to existing consumers
#                         payload = obj.get("payload")
#                         if payload is not None:
#                             data_to_forward = json.dumps(payload).encode("utf-8")
#                 except Exception:
#                     # If decode/parse fails, forward raw data
#                     pass
#             # -------------------------------------------------------------------------

#             # fan-out
#             for name, port in CONSUMER_PORTS.items():
#                 try:
#                     # send_sock.sendto(data, (UDP_IP, port))
#                     send_sock.sendto(data_to_forward, (UDP_IP, port))

#                     # if LOG_FANOUT:
#                     #     print(f"[Dispatcher] Forwarded -> {name} @ {UDP_IP}:{port}")
#                 except Exception as se:
#                     print(f"[Dispatcher] Send error to {name}@{UDP_IP}:{port} -> {se}")

#     finally:
#         try: recv_sock.close()
#         except Exception: pass
#         try: send_sock.close()
#         except Exception: pass
#         print("[Dispatcher] Stopped cleanly")
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

    print(f"\033[91m[Dispatcher] Listening on {UDP_IP}:{UDP_PORT}\033[0m")

    try:
        while not stop_event.is_set():
            try:
                data, addr = recv_sock.recvfrom(65535)
                print("[Dispatcher][CHECK] first50 =", data[:50])
                print(f"[Dispatcher][DEBUG] recvfrom addr={addr} bytes={len(data)}")

            except socket.timeout:
                continue
            except OSError as e:
                if stop_event.is_set():
                    break
                print(f"[Dispatcher] Socket error (recv): {e}")
                time.sleep(0.2)
                continue

            # logging
            if LOG_PAYLOADS:
                try:
                    _ = json.loads(data.decode("utf-8", errors="ignore"))
                except Exception:
                    print(f"[Dispatcher] Received {len(data)} bytes from {addr}")
            else:
                print(f"[Dispatcher] Received {len(data)} bytes from {addr}")

            # ---- BUFFER UNWRAP + ACK (ACK AFTER FORWARD) ----
            data_to_forward = data
            ack_msg_id = None

            if ACK_ENABLED:
                try:
                    obj = json.loads(data.decode("utf-8", errors="ignore"))

                    if isinstance(obj, dict) and obj.get("type") == "buffered_event":
                        ack_msg_id = obj.get("msg_id")
                        print(f"[Dispatcher] buffered_event detected from {addr}, msg_id={ack_msg_id}")

                        # unwrap payload for forwarding to existing consumers
                        payload = obj.get("payload")
                        if payload is not None:
                            data_to_forward = json.dumps(payload).encode("utf-8")

                except Exception:
                    # If decode/parse fails, forward raw data
                    ack_msg_id = None
                    data_to_forward = data

            # fan-out (always forward first)
            for name, port in CONSUMER_PORTS.items():
                try:
                    send_sock.sendto(data_to_forward, (UDP_IP, port))
                except Exception as se:
                    print(f"[Dispatcher] Send error to {name}@{UDP_IP}:{port} -> {se}")

            # ACK only AFTER we attempted forwarding
            if ACK_ENABLED and ack_msg_id:
                try:
                    ack_msg = {"type": "ack", "msg_id": ack_msg_id}
                    print(
                        f"[Dispatcher][DEBUG] ACK about to send: msg_id={ack_msg_id} "
                        f"recv_addr={addr} ack_dest=({addr[0]},{ACK_PORT})"
                    )
                    send_sock.sendto(json.dumps(ack_msg).encode("utf-8"), (addr[0], ACK_PORT))
                    print(f"[Dispatcher][DEBUG] ACK sendto OK msg_id={ack_msg_id} dest=({addr[0]},{ACK_PORT})")
                except Exception as ae:
                    print(f"[Dispatcher] ACK send failed to {addr[0]}:{ACK_PORT} -> {ae}")
            # -----------------------------------------------

    finally:
        try:
            recv_sock.close()
        except Exception:
            pass
        try:
            send_sock.close()
        except Exception:
            pass
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
