import os
import pwd
import uuid
import json
import socket
import subprocess
from datetime import datetime
from collections import defaultdict

# ---------------- CONFIG ----------------
CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH) as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
UDP_PORT = config["udp"]["server_port"]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

IGNORE_PROCESSES = {
    "/usr/bin/python3.12",
    "/snap/firefox/6836/usr/lib/firefox/firefox",
    "/usr/bin/gnome-shell",
    "/usr/lib/erlang/erts-13.2.2.5/bin/beam.smp",
    "/usr/bin/bash",
    "/usr/libexec/tracker-miner-fs-3",
    # "/usr/bin/nano"   # uncomment if you want to ignore nano
}

SYSCALL_MAP = {
    "257": "openat",
    "87": "unlink",
    "82": "rename",
    "1": "write",
    "90": "truncate",
    "91": "ftruncate",
    "268": "renameat2"
}

hostname = os.uname().nodename
mac_address = ':'.join(f"{(uuid.getnode() >> i) & 0xff:02x}" for i in range(40, -1, -8))


def build_event(path, exe, syscall, auid, uid, pid, raw_lines):
    try:
        username = pwd.getpwuid(int(auid)).pw_name if auid and auid.isdigit() else "unknown"
    except KeyError:
        username = "unknown"

    return {
        "timestamp": datetime.now().isoformat(),
        "hostname": hostname,
        "mac_address": mac_address,
        "auid": auid,
        "uid": uid,
        "username": username,
        "pid": pid,
        "exe": exe,
        "syscall": syscall,
        "operation": SYSCALL_MAP.get(syscall, "unknown"),
        "file_path": path,
        "raw": "\n".join(raw_lines),
        "topic": "bulk-data-events"
    }


def main():
    print("\033[1;92m!!!!!!!!! Bulk Data Producer Running (auditd live stream) !!!!!!\033[0m")

    cmd = ["tail", "-F", "/var/log/audit/audit.log"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, stderr=subprocess.DEVNULL)

    current_events = defaultdict(list)  # event_id -> lines
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line or "ueba_bulk_fs" not in line:
                continue

            # Extract event id from msg=audit(...)
            event_id = None
            for part in line.split():
                if part.startswith("msg=audit("):
                    event_id = part.split(":")[-1].rstrip(")")
                    break
            if not event_id:
                continue

            # Collect lines for this event id
            current_events[event_id].append(line)
            lines = current_events[event_id]

            # Process once we have both SYSCALL and PATH records
            has_syscall = any("SYSCALL" in l for l in lines)
            has_path = any("PATH" in l and "name=" in l and "name=(null)" not in l for l in lines)

            if has_syscall and has_path:
                exe, path, syscall, auid, uid, pid = None, None, None, None, None, None
                for l in lines:
                    for part in l.split():
                        if part.startswith("exe="):
                            exe = part.split("=", 1)[1].strip('"')
                        elif part.startswith("name=") and part != "name=(null)":
                            path = part.split("=", 1)[1].strip('"')
                        elif part.startswith("syscall="):
                            syscall = part.split("=")[1]
                        elif part.startswith("auid="):
                            auid = part.split("=")[1]
                        elif part.startswith("uid=") and uid is None:
                            uid = part.split("=")[1]
                        elif part.startswith("pid="):
                            pid = part.split("=")[1]

                if exe and exe not in IGNORE_PROCESSES and path:
                    evt = build_event(path, exe, syscall, auid, uid, pid, lines)
                    sock.sendto(json.dumps(evt).encode("utf-8"), (UDP_IP, UDP_PORT))
                    print(f"[UDP] Sent event {evt['operation']} by {evt['username']} on {path}")

                # cleanup
                del current_events[event_id]

    except KeyboardInterrupt:
        print("\nStopped by user.")
    finally:
        proc.kill()
        sock.close()


if __name__ == "__main__":
    main()
