import json
import time
import psutil
import platform
import socket
import uuid
from datetime import datetime
from kafka import KafkaProducer

# === Kafka Config ===
KAFKA_TOPIC = "process-events"
BOOTSTRAP_SERVERS = ['localhost:9092']

# === Platform Flags ===
IS_WINDOWS = platform.system().lower() == 'windows'
IS_LINUX = platform.system().lower() == 'linux'
IS_MAC = platform.system().lower() == 'darwin'

# === Kafka Producer Init ===
producer = KafkaProducer(
    bootstrap_servers=BOOTSTRAP_SERVERS,
    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
    compression_type='gzip',
    acks='all',
    linger_ms=500
)

# === System Info ===
def get_system_info():
    lan_ip = None
    for iface_addrs in psutil.net_if_addrs().values():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                lan_ip = addr.address
                break
        if lan_ip:
            break
    return {
        "hostname": socket.gethostname(),
        "mac_address": ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(40, -1, -8)]),
        "lan_ip": lan_ip or "Unknown",
        "os": platform.system()
    }

# === Track seen processes ===
seen_pids = set()

def poll_processes():
    global seen_pids

    current_pids = set(psutil.pids())
    new_pids = current_pids - seen_pids

    for pid in new_pids:
        try:
            proc = psutil.Process(pid)
            info = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "process_created",
                "pid": pid,
                "ppid": proc.ppid(),
                "username": proc.username(),
                "cmdline": ' '.join(proc.cmdline()),
                "exe": proc.exe() if proc.exe() else "",
                "cwd": proc.cwd() if proc.cwd() else "",
                "create_time": datetime.fromtimestamp(proc.create_time()).isoformat(),
                **get_system_info()
            }
            producer.send(KAFKA_TOPIC, info)
            print("Sent process event:", json.dumps(info, indent=2))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    seen_pids = current_pids

def main():
    print("✅ Started Process Monitor Producer")
    while True:
        try:
            poll_processes()
            time.sleep(5)
        except KeyboardInterrupt:
            print("Interrupted by user.")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
