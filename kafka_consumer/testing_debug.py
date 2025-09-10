# file: send_test_app_usage.py
import json, socket
from datetime import datetime, timedelta

CONFIG_PATH = "/home/config.json"       # same as consumer
with open(CONFIG_PATH, "r") as f:
    cfg = json.load(f)

UDP_IP   = cfg["udp"]["server_ip"]
UDP_PORT = 6001

now = datetime.now()
record = {
    "username": "testuser",
    "process_name": "nmap",                 # sensitive -> rule hit
    "pid": 43210,
    "ppid": 1,
    "cmdline": "/home/testuser/.local/bin/nmap -sS 10.0.0.1",  # suspicious path -> rule hit
    "terminal": "pts/1",
    "status": "running",
    "cpu_percent": 85.0,                    # high CPU -> rule hit
    "memory_percent": 60.0,                 # high Mem -> rule hit
    "start_time": (now - timedelta(minutes=3)).isoformat(),
    "end_time": now.isoformat(),
    "duration_secs": 180.0,
    "timestamp": now.isoformat(),
    "event": "launch"                       # ensures DB insert path executes
}

metrics = {
    "topic": "system-metrics",
    "application_usage": [record],
    # optional latency fields (keeps insert_latency_record happy)
    "username": "testuser",
    "cpu_usage": 15.2,
    "memory_usage": 42.0,
    "startup_latency": 0.12,
    "response_time": 0.05,
    "io_wait_time": 0.01,
    "disk_read_rate": 1.2,
    "disk_write_rate": 0.8,
    "avg_load": 0.5,
    "network_bytes_sent": 1024, 
    "network_bytes_recv": 2048,
    "context_switches": 10,
    "system_temperature": 55.0,
    "timestamp": now.isoformat(),
}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(json.dumps(metrics).encode("utf-8"), (UDP_IP, UDP_PORT))
print("Sent test application_usage event to", UDP_IP, UDP_PORT)
