import os
import json
import time
import socket
import uuid
import psutil
import ipaddress
import subprocess
from datetime import datetime

# Debounce cache to suppress duplicate events
LAST_EVENT = {}

# ===== Load Configuration =====
CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH) as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
UDP_PORT = config["udp"]["server_port"]
MONITORED_DIRS = [os.path.realpath(p) for p in config.get("monitored_dirs", []) if os.path.exists(p)]

# ===== Network Setup =====
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
hostname = os.uname().nodename
mac_address = ':'.join(f"{(uuid.getnode() >> i) & 0xff:02x}" for i in range(40, -1, -8))
USERNAME = psutil.users()[0].name if psutil.users() else "Unknown"


def get_lan_and_internet_ips():
    lan_ip, internet_ip = None, None
    for iface_addrs in psutil.net_if_addrs().values():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
                if not ip.startswith("127.") and ipaddress.ip_address(ip).is_private:
                    lan_ip = ip
                    break
        if lan_ip:
            break
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        internet_ip = s.getsockname()[0]
        s.close()
    except Exception:
        internet_ip = "Unknown"
    return lan_ip or "Unknown", internet_ip or "Unknown"


lan_ip, internet_ip = get_lan_and_internet_ips()

# ===== Ignore patterns to avoid background/system noise =====
IGNORE_KEYWORDS = [
    # datIGNORE_KEYWORDS = [
    # database / cache / data engines
    "postgres", "pg_", "/pg_", "PG_VERSION", "pg_internal", "pg_filenode",
    "/base/", "/global/", "/pg_wal/", "/pg_stat/", "/pg_multixact/",
    "/pg_subtrans/", "/pg_commit_ts/", "/pg_serial/", "/pg_tblspc/",
    "/pg_snapshots/", "/pg_stat_tmp/", "/pg_replslot/", "/pg_twophase/",
    "/pg_notify/", "/pg_logical/", "/pg_dynshmem/",

    # git / vcs metadata
    ".git", ".gitconfig", "/.git/", "/.gitmodules", "/.gitignore",
    "/.gitattributes", "/.github/", "/.vscode/", "/.idea/", "/.svn/",
    "/.hg/", "/.bzr/",

    # caches / config / system data
    ".cache", ".npm", ".yarn", ".pip", ".cargo", ".gradle", ".m2",
    "__pycache__", ".local/share", ".local/state", ".mozilla",
    ".config", ".thumbnails",

    # temp / swap / backup
    ".tmp", ".swp", ".swo", ".swx", ".bak", ".backup", "~", ".partial", ".part",

    # logs / locks / runtime
    ".journal", ".lock", ".log", ".pid", ".sock",

    # mail system noise
    "maildrop", "Maildir", "/var/mail", "/var/spool/mail",

    # trash / autosave / history
    "Trash", ".local/share/Trash", ".xsession-errors",
    ".bash_history", ".recently-used"
]

def parse_audit_line(line):
    if 'name=' not in line:
        return None

    # Extract and sanitize file path
    path = next((p.split("=", 1)[1].strip('"') for p in line.split() if p.startswith("name=")), None)
    if not path or path in ["/", ".", "(null)"]:
        return None

    real_path = os.path.realpath(path)
    basename = os.path.basename(real_path)

    # Only monitor configured directories
    if not any(real_path.startswith(d) for d in MONITORED_DIRS):
        return None

    # Ignore known background/cache/tmp/database noise
    if any(k in real_path for k in IGNORE_KEYWORDS):
        return None

    # Ignore kernel, pseudo, or hardware paths
    SYSTEM_NOISE = [
        "/sys", "/proc", "/dev", "/run", "/tmp", "/var/tmp", "/var/cache",
        "/virtual", "/devices", "/class", "/dmi", "/id", "/bus", "/kernel",
        "/udev", "/net", "/power", "/firmware"
    ]
    if any(seg in real_path for seg in SYSTEM_NOISE):
        return None

    # Skip pseudo file or hardware node names
    if basename.lower() in [
        "virtual", "devices", "sys", "class", "dmi", "id",
        "firmware", "bus"
    ]:
        return None

    # Skip home directory self-mod updates (like opening new terminal)
    user_home = os.path.expanduser("~")
    if real_path == user_home or real_path.rstrip("/") == os.path.dirname(user_home):
        return None

    # Skip pgAdmin or pg-related session/config files
    if "/.pgadmin/" in real_path or "pgadmin" in real_path.lower():
        return None

    # Ignore directory-only metadata updates (we only care about actual files)
    if os.path.isdir(real_path):
        return None

    if any(seg in real_path for seg in [
        ".bashrc", ".bash_profile", ".bash_logout", ".profile",
        ".python_history", ".command_log", ".lesshst", ".wget-hsts",
        ".Xauthority", ".pki", ".gnupg", ".ssh", ".history",
        ".local/share/recently-used.xbel",
        "2F686F6D65", "VirtualBox VMs", "VMs", "snapshots"
    ]):
        return None

    # Ignore Node/NVM related noise (aliases, completions, version switches)
    if any(seg in real_path for seg in [
        "/.nvm/", ".nvm/", "nvm.sh", "bash_completion",
        "/alias/", "/versions/", "/lts/", "/default"
    ]):
        return None


    # Detect event type (handle rename and reduce duplicates)
    if "nametype=CREATE" in line and "nametype=DELETE" in line:
        etype = "moved"
    elif "nametype=CREATE" in line:
        etype = "created"
    elif "nametype=DELETE" in line:
        etype = "deleted"
    elif "nametype=NORMAL" in line:
        etype = "modified"
    elif "nametype=RENAME" in line:
        etype = "moved"
    else:
        return None
    
        # Ignore pseudo symlinks (proc/self, environment-linked, or mirrored system dirs)
    if any(seg in real_path for seg in [
        "/self/", "/proc/self/", "/proc/", "/home/", "/etc/", "/usr/", "/lib/", "/var/",
        "/run/", "/bin/", "/sbin/", "/snap/", "/boot/"
    ]) and real_path.startswith("/home") and "UEBA_BACKEND" in real_path:
        return None


    # Debounce repeated identical events (e.g. nano multi-writes)
    now = time.time()
    last = LAST_EVENT.get(real_path)
    if last and (now - last < 1.0):  # skip duplicates within 1 second
        return None
    LAST_EVENT[real_path] = now

    return etype, real_path



# ===== Stream Audit Log (Live) =====
def stream_audit_log():
    log_path = "/var/log/audit/audit.log"
    # suppress tail noise (rotation / permission messages)
    with subprocess.Popen(
        ["tail", "-F", log_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,   # this cleans the “has been replaced” spam
        text=True
    ) as proc:
        for line in proc.stdout:
            yield line


# ===== Main =====
def main():
    print("\033[1;92m!!!!!!!!! File System Monitoring via Auditd (Live) Running !!!!!!\033[0m")
    print("Monitoring directories:")
    for d in MONITORED_DIRS:
        print(f"   {d}")
    time.sleep(1)

    for line in stream_audit_log():
        parsed = parse_audit_line(line)
        if not parsed:
            continue

        etype, path = parsed

        event_info = {
            "Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS",
            "Event Sub Type": f"FILE_{etype.upper()}",
            "Event Details": f"File {etype} at {path} on host {hostname}",
            "Value": path
        }

        metrics = {
            "timestamp": datetime.now().isoformat(),
            "hostname": hostname,
            "mac_address": mac_address,
            "username": USERNAME,
            "ip_addresses": (lan_ip, internet_ip),
            "directory": path,
            "event_type": etype
        }

        event_data = {
            "timestamp": metrics["timestamp"],
            "username": metrics["username"],
            "event_info": event_info,
            "metrics": metrics,
            "topic": "sensitive-events"
        }

        sock.sendto(json.dumps(event_data).encode("utf-8"), (UDP_IP, UDP_PORT))
        print(f"[AUDITD→UDP] {etype.upper()} {path}")


if __name__ == "__main__":
    main()
