import os
import time
import json
import socket
import uuid
import platform
import psutil
from datetime import datetime
from kafka import KafkaProducer
import subprocess

# === Platform Flags ===
IS_WINDOWS = platform.system().lower() == 'windows'
IS_LINUX = platform.system().lower() == 'linux'
IS_MAC = platform.system().lower() == 'darwin'

# === Kafka Config ===
KAFKA_TOPIC = "cmd-events"
BOOTSTRAP_SERVERS = ["localhost:9092"]
POLL_INTERVAL = 10  # seconds

# === Kafka Producer Setup ===
producer = KafkaProducer(
    bootstrap_servers=BOOTSTRAP_SERVERS,
    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
    compression_type='gzip',
    acks='all',
    linger_ms=500
)

# === Metadata Enrichment ===
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
        "os": platform.system(),
        "username": psutil.users()[0].name if psutil.users() else "Unknown",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

# === Track previously seen commands ===
seen_commands = set()


# === Global state for tracking file positions ===
# history_file_offsets = {}

# def get_linux_mac_history():
#     home = os.path.expanduser("~")
#     possible_files = [".bash_history", ".zsh_history"]
#     commands = []

#     for hist_file in possible_files:
#         path = os.path.join(home, hist_file)
#         if not os.path.exists(path):
#             continue

#         # Start from end of file on first run
#         if path not in history_file_offsets:
#             history_file_offsets[path] = os.path.getsize(path)

#         with open(path, 'r', encoding='utf-8', errors='ignore') as f:
#             f.seek(history_file_offsets[path])
#             new_lines = f.readlines()
#             history_file_offsets[path] = f.tell()  # Update offset

#         for line in new_lines:
#             line = line.strip()
#             if line and line not in seen_commands:
#                 seen_commands.add(line)
#                 commands.append(line)

#     return commands


# last_log_pos = 0
# session_log_path = "/tmp/session_log"

# def get_real_time_typed_commands():
#     global last_log_pos
#     commands = []

#     if not os.path.exists(session_log_path):
#         return []

#     with open(session_log_path, 'r', encoding='utf-8', errors='ignore') as f:
#         f.seek(last_log_pos)
#         new_lines = f.readlines()
#         last_log_pos = f.tell()

#     for line in new_lines:
#         line = line.strip()
#         if line and line not in seen_commands:
#             seen_commands.add(line)
#             # crude filter: skip prompt and echo lines
#             if not line.startswith(tuple("[]$#")):
#                 commands.append(line)

#     return commands
import subprocess
from datetime import datetime

script_start_time = datetime.now()
print("Script started at:", script_start_time.strftime("%Y-%m-%d %H:%M:%S"))

def get_linux_mac_history():
    commands = []
    try:
        output = subprocess.check_output(['bash', '-i', '-c', 'history'], text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            parts = line.strip().split(None, 3)
            if len(parts) == 4:
                _, date_str, time_str, cmd = parts
                try:
                    ts = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
                    if ts >= script_start_time:
                        commands.append(cmd.strip())
                except ValueError:
                    continue
    except Exception as e:
        print("Error reading history:", e)

    return commands


def get_windows_history():
    commands = []
    try:
        cmd = 'powershell "Get-History | ForEach-Object { $_.CommandLine }"'
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
        for line in output.strip().splitlines():
            line = line.strip()
            if line and line not in seen_commands:
                seen_commands.add(line)
                commands.append(line)
    except Exception:
        pass
    return commands

# === Poll + Send Commands ===
# def poll_and_send():
#     print(platform.system().lower())
#     if IS_LINUX or IS_MAC:
#         # cmds = get_linux_mac_history()
#         cmds = get_real_time_typed_commands()
#     elif IS_WINDOWS:
#         cmds = get_windows_history()
#     else:
#         cmds = []

#     for cmd in cmds:
#         event = {
#             "event_type": "cmd_exec",
#             "command": cmd,
#             **get_system_info()
#         }
#         producer.send(KAFKA_TOPIC, value=event)
#         print("Sent command:", json.dumps(event, indent=2))
def get_auditd_commands():
    commands = []
    try:
        result = subprocess.run(
            ["ausearch", "-k", "user-cmd", "-ts", "recent"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        if result.returncode != 0 or not result.stdout.strip():
            return []

        blocks = result.stdout.split("----")
        for block in blocks:
            cmd = []
            tty_allowed = False
            skip = False

            for line in block.strip().splitlines():
                if "type=EXECVE" in line:
                    for part in line.strip().split():
                        if part.startswith("a") and "=" in part:
                            val = part.split("=", 1)[1].strip('"')
                            cmd.append(val)

                if "type=SYSCALL" in line:
                    if "tty=pts" in line:
                        tty_allowed = True
                    if "comm=\"ausearch\"" in line or "comm=\"grep\"" in line:
                        skip = True  # don't log internal tools

            if cmd and tty_allowed and not skip:
                full_cmd = " ".join(cmd)
                if full_cmd not in seen_commands:
                    seen_commands.add(full_cmd)
                    commands.append(full_cmd)

    except Exception as e:
        print("Error reading audit logs:", e)

    return commands




def poll_and_send():
    os_name = platform.system().lower()
    # print(os_name)

    if os_name in ("linux"):
        # cmds = get_linux_mac_history() 
        cmds = get_auditd_commands() 
    elif os_name == "windows":
        cmds = get_windows_history()
    else:
        cmds = []

    for cmd in cmds:
        event = {
            "event_type": "cmd_exec",
            "command": cmd,
            **get_system_info()
        }
        producer.send(KAFKA_TOPIC, value=event)
        print("Sent command:", json.dumps(event, indent=2))


def main():
    print("Monitoring command history...")
    while True:
        try:
            poll_and_send()
            time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            print("Stopped by user.")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
