#!/usr/bin/env python3
import os
import sys
import json
import time
import logging
import socket

# Make parent directory importable so we can import new_log_monitor
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from datetime import datetime
from kafka_producer.new_log_monitor import track_process_executions

# ─── Logger ──────────────────────────────────────────────────────────────────
LOG = logging.getLogger("ProcessMonitoringProducer")
if not LOG.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

# ─── Load config ─────────────────────────────────────────────────────────────
CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH) as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
UDP_PORT = config["udp"]["server_port"]

# New dedicated topic for process monitoring
PROCESS_TOPIC = "process-monitoring"

# independent scan / batch settings (can also be put in config if you want)
PROCESS_SCAN_INTERVAL = int(config.get("PROCESS_SCAN_INTERVAL", 2))      # poll_interval for track_process_executions
BUFFER_SEND_INTERVAL = int(config.get("PROCESS_BUFFER_SEND_INTERVAL", 5))  # how often to send a batch

# ─── UDP socket ──────────────────────────────────────────────────────────────
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def run_process_producer():
    """
    Continuously track process executions and send them in batches over UDP.

    Payload format (per batch):

    {
        "topic": "process-monitoring",
        "process_events": [ {...}, {...}, ... ]
    }

    NOTE: Ensure the consumer accepts topic == "process-monitoring"
    and reads metrics["process_events"].
    """

    buffer = []
    last_send = time.time()

    LOG.info(
        "!!!!!!!!! Process Monitoring Producer running (UDP) "
        f"→ {UDP_IP}:{UDP_PORT}, topic='{PROCESS_TOPIC}' !!!!!!"
    )
    print(
        "\033[1;92m!!!!!!!!! Process Monitoring Producer running (UDP) !!!!!!\033[0m"
    )

    try:
        # track_process_executions yields individual process lifecycle events
        for event in track_process_executions(poll_interval=PROCESS_SCAN_INTERVAL):
            buffer.append(event)

            # small sleep to avoid CPU starvation
            time.sleep(0.05)

            now = time.time()
            if now - last_send >= BUFFER_SEND_INTERVAL:
                if buffer:
                    payload = {
                        "topic": PROCESS_TOPIC,
                        "process_events": buffer,
                    }

                    try:
                        sock.sendto(
                            json.dumps(payload, default=str).encode("utf-8"),
                            (UDP_IP, UDP_PORT),
                        )
                        print(
                            f"\033[1;36m[PROCESS BATCH] Sent {len(buffer)} process events\033[0m"
                        )
                        LOG.info("Sent %d process events", len(buffer))
                    except Exception as e:
                        LOG.error("Failed to send process batch over UDP: %s", e)

                    buffer.clear()

                last_send = now

    except KeyboardInterrupt:
        LOG.info("KeyboardInterrupt received, flushing remaining events and exiting...")
        if buffer:
            payload = {
                "topic": PROCESS_TOPIC,
                "process_events": buffer,
            }
            try:
                sock.sendto(
                    json.dumps(payload, default=str).encode("utf-8"),
                    (UDP_IP, UDP_PORT),
                )
                print(
                    f"\033[1;36m[PROCESS BATCH] Sent final {len(buffer)} process events before exit\033[0m"
                )
                LOG.info("Sent final %d process events", len(buffer))
            except Exception as e:
                LOG.error("Failed to send final batch over UDP: %s", e)
        print("\033[1;91mProcess Monitoring Producer stopped.\033[0m")
    except Exception as e:
        LOG.error("Unhandled exception in process producer: %s", e)
        raise


def main():
    run_process_producer()


if __name__ == "__main__":
    main()
