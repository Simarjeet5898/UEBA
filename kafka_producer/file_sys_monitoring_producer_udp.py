import os
import json
import time
import uuid
import logging
from datetime import datetime
# import pyinotify
from inotify_simple import INotify, flags
import psutil
import socket
import ipaddress
import sys
import hashlib

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from kafka_producer.new_log_monitor import get_lan_and_internet_ips

CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH) as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
UDP_PORT = config["udp"]["server_port"]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

IGNORE_PATTERNS = [".1", ".gz", ".old", ".bak", ".swp", ".tmp", ".swo", ".swx", ".log", ".bash_history"]
IGNORE_DIRS = [
    "/proc", "/sys", "/dev",
    os.path.expanduser("~/.config"),
    os.path.expanduser("~/.cache"),
    os.path.expanduser("~/.pgadmin"),
    os.path.expanduser("~/.local")
]
IGNORE_DIRS = [os.path.realpath(d) for d in IGNORE_DIRS]

INOTIFY_MASK = (
    flags.CREATE
    | flags.DELETE
    | flags.MOVED_FROM
    | flags.MOVED_TO
    | flags.MODIFY
    | flags.ATTRIB
    | flags.OPEN
    | flags.CLOSE_WRITE
    | flags.CLOSE_NOWRITE
)

EVENT_MAPPING = {
    "created": {
        "Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS",
        "Event Sub Type": "FILE_CREATION",
        "Event Details": "New file created in the directory"
    },
    "deleted": {
        "Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS",
        "Event Sub Type": "FILE_DELETION",
        "Event Details": "File deleted in the directory"
    },
    "modified": {
        "Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS",
        "Event Sub Type": "FILE_MODIFICATION",
        "Event Details": "File modified in the directory"
    },
    "moved": {
        "Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS",
        "Event Sub Type": "FILE_MOVED",
        "Event Details": "File moved to a different directory"
    },
    "renamed": {
        "Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS",
        "Event Sub Type": "FILE_RENAME",
        "Event Details": "File renamed in the same directory"
    },
    "open": {
        "Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS",
        "Event Sub Type": "FILE_OPEN",
        "Event Details": "File opened in the directory"
    },
    "close_write": {
        "Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS",
        "Event Sub Type": "FILE_CLOSE_WRITE",
        "Event Details": "File closed after write"
    },
    "close_nowrite": {
        "Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS",
        "Event Sub Type": "FILE_CLOSE_NOWRITE",
        "Event Details": "File closed without write"
    },
    "attrib_change": {
        "Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS",
        "Event Sub Type": "FILE_ATTRIBUTE_CHANGE",
        "Event Details": "File attributes changed"
    }
}


USERNAME = psutil.users()[0].name if psutil.users() else "Unknown"

def get_lan_and_internet_ips():
    lan_ip = None
    internet_ip = None
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
hostname = os.uname().nodename
mac_address = ':'.join(f"{(uuid.getnode() >> i) & 0xff:02x}" for i in range(40, -1, -8))


class EventHandler:
    def __init__(self):
        self.move_from = {}
        self.move_timeout = 1  # seconds

        # --- added for creation/modify coalescing ---
        self.coalesce_window = 0.5  # seconds
        self.suppress = {}          # path -> {"until": ts, "types": set([...])}
        self.last_modified = {}     # path -> last emit ts

    # ---------------- helpers (added) ----------------
    def _arm_suppress(self, path, types):
        self.suppress[path] = {
            "until": time.time() + self.coalesce_window,
            "types": set(types),
        }

    def _should_suppress(self, path, etype):
        info = self.suppress.get(path)
        if not info:
            return False
        if time.time() <= info["until"] and etype in info["types"]:
            return True
        return False

    # -------------------------------------------------
    def should_ignore(self, path):
        real_path = os.path.realpath(path)

        for ignored in IGNORE_DIRS:
            try:
                if os.path.commonpath([real_path, ignored]) == ignored:
                    return True
            except Exception:
                pass

        if "BraveSoftware/Brave-Browser" in real_path:
            return True

        if "/snap/" in real_path:
            return True

        filename = os.path.basename(real_path)

        if any(filename.endswith(pat) for pat in IGNORE_PATTERNS):
            return True

        if filename.startswith(".goutputstream-"):
            return True

        return False

    def compute_file_hash(self, path):
        try:
            if not os.path.isfile(path):
                return None
            hasher = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None

    # --------------------------------------------------------
    # MAIN DISPATCHER HANDLING ALL EVENTS
    # --------------------------------------------------------
    def dispatch(self, event, watched_dir):
        full_path = os.path.join(watched_dir, event.name)

        # ignore directory-level events
        if event.mask & flags.ISDIR:
            return
        if os.path.isdir(full_path):
            return

        if self.should_ignore(full_path):
            return

        mask = flags.from_mask(event.mask)

        # ---------------- MOVE HANDLING (unchanged) ---------------- #
        if flags.MOVED_FROM in mask:
            self.move_from[event.cookie] = (full_path, time.time())
            return

        if flags.MOVED_TO in mask:
            if event.cookie in self.move_from:
                src, t = self.move_from[event.cookie]
                del self.move_from[event.cookie]

                if time.time() - t <= self.move_timeout:
                    # distinguish rename vs move
                    same_dir = os.path.dirname(src) == os.path.dirname(full_path)
                    etype = "renamed" if same_dir else "moved"
                    self.process(etype, src, full_path)
                    return

            # fallback: treat as move
            self.process("moved", full_path, full_path)
            return

        # ---------------- CREATION (coalesced) ---------------- #
        if flags.CREATE in mask:
            # emit exactly one "created"
            self.process("created", full_path, None)
            # suppress OS follow-ups for creation burst
            self._arm_suppress(full_path, {"open", "attrib_change", "close_write", "close_nowrite"})
            return

        # ---------------- DELETE (unchanged) ---------------- #
        if flags.DELETE in mask:
            self.process("deleted", full_path, None)
            return

        # ---------------- MODIFY (coalesced) ---------------- #
        if flags.MODIFY in mask:
            now = time.time()
            last = self.last_modified.get(full_path)
            if last is not None and (now - last) < self.coalesce_window:
                # suppress rapid duplicate modifies
                return
            # emit exactly one "modified"
            self.process("modified", full_path, None)
            self.last_modified[full_path] = now
            # suppress the immediate open/close noise after modification
            self._arm_suppress(full_path, {"open", "close_write", "close_nowrite"})
            return

        # ---------------- OTHER BASIC EVENTS (guarded by suppression) ---------------- #

        if flags.OPEN in mask:
            if self._should_suppress(full_path, "open"):
                return
            self.process("open", full_path, None)
            return

        if flags.CLOSE_WRITE in mask:
            if self._should_suppress(full_path, "close_write"):
                return
            self.process("close_write", full_path, None)
            return

        if flags.CLOSE_NOWRITE in mask:
            if self._should_suppress(full_path, "close_nowrite"):
                return
            self.process("close_nowrite", full_path, None)
            return

        if flags.ATTRIB in mask:
            if self._should_suppress(full_path, "attrib_change"):
                return
            self.process("attrib_change", full_path, None)
            return

    # --------------------------------------------------------
    # PROCESS EVENT (unchanged)
    # --------------------------------------------------------
    def process(self, event_type, src_path, dest_path):
        if event_type not in EVENT_MAPPING:
            return

        info = EVENT_MAPPING[event_type]

        # moved event formatting
        if event_type in ("moved", "renamed"):
            event_info = {
                "Event Type": info["Event Type"],
                "Event Sub Type": info["Event Sub Type"],
                "Event Details": f"{info['Event Details']}: from {src_path} to {dest_path} on host {hostname}",
                "Value": {"from": src_path, "to": dest_path}
            }
        else:
            event_info = {
                "Event Type": info["Event Type"],
                "Event Sub Type": info["Event Sub Type"],
                "Event Details": f"{info['Event Details']} at {src_path} on host {hostname}",
                "Value": src_path
            }

        # compute file hash only for modified
        file_hash = None
        if event_type == "modified":
            file_hash = self.compute_file_hash(src_path)

        metrics = {
            "timestamp": datetime.now().isoformat(),
            "hostname": hostname,
            "mac_address": mac_address,
            "username": USERNAME,
            "ip_addresses": get_lan_and_internet_ips(),
            "directory": src_path,
            "event_type": event_type,
            "file_hash": file_hash
        }

        event_data = {
            "timestamp": metrics["timestamp"],
            "username": metrics["username"],
            "event_info": event_info,
            "metrics": metrics,
            "topic": "sensitive-events"
        }

        sock.sendto(json.dumps(event_data).encode("utf-8"), (UDP_IP, UDP_PORT))
        print(f"[UDP] Sent: {event_type} at {src_path}")


def load_monitoring_config():
    try:
        monitored = [d for d in config.get("monitored_dirs", []) if os.path.exists(d)]
        sensitive = [d for d in config.get("sensitive_dirs", []) if os.path.exists(d)]
        return monitored, sensitive
    except Exception as e:
        logging.error(f"Failed to load config: {e}")
        return [], []


def main():
    print("\033[1;92m!!!!!!!!! File System Monitoring Producer Running !!!!!!\033[0m")

    monitored_dirs, _ = load_monitoring_config()

    if not monitored_dirs:
        print("No valid monitored directories found. Exiting.")
        return

    handler = EventHandler()
    notifier = INotify()

    watch_descriptors = {}

    for d in monitored_dirs:
        print(f"Watching: {d}")
        try:
            # wd = notifier.add_watch(d, INOTIFY_MASK, flags.ADD_MASK)
            wd = notifier.add_watch(d, INOTIFY_MASK)    
            watch_descriptors[wd] = d
        except Exception as e:
            logging.error(f"Failed to add watch: {d} - {e}")

    while True:
        events = notifier.read(timeout=1000)
        for event in events:
            watched_dir = watch_descriptors.get(event.wd, None)
            if watched_dir:
                handler.dispatch(event, watched_dir)



if __name__ == "__main__":
    main()
