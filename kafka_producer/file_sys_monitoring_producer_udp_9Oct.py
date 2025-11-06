import os
import json
import time
import socket
import uuid
import psutil
import ipaddress
import subprocess
from datetime import datetime
import re
from threading import Thread
from inotify_simple import INotify, flags


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
    ".bash_history", ".recently-used",  ".sudo_as_admin_successful"
]


# ===== Read/Write flag mask and event aggregation =====
WRITE_FLAGS = 0x1 | 0x2 | 0x40 | 0x200 | 0x400  # WRONLY | RDWR | CREAT | TRUNC | APPEND
MSG_RE = re.compile(r'msg=audit\((\d+\.\d+):(\d+)\)')
# put near WRITE_FLAGS/MSG_RE
SYSCALL_MAP_X86_64 = {
    "0": "read",
    "1": "write",
    "2": "open",
    "257": "openat",
    "87": "unlink",
    "263": "unlinkat",
    "82": "rename",
    "316": "renameat2",
    "276": "renameat",
    "76": "truncate",
    "77": "ftruncate",
}
def _normalize_syscall(sc, arch):
    # if already a name, keep; if numeric and arch is x86_64, map common ones
    if sc and sc.isalpha():
        return sc
    if arch in ("c000003e", "x86_64") and sc in SYSCALL_MAP_X86_64:
        return SYSCALL_MAP_X86_64[sc]
    return sc

def _get_flags(rec):
    """Return open/openat flag value (auto-detect hex or decimal)."""
    sc = rec.get("syscall", "")
    raw = rec.get("a2") if sc in ("openat",) else rec.get("a1")
    if not raw:
        return 0
    try:
        return int(raw, 0)  # auto base (0x.. or decimal)
    except ValueError:
        return 0


SYSTEM_NOISE = [
    "/sys", "/proc", "/dev", "/run", "/tmp", "/var/tmp", "/var/cache",
    "/virtual", "/devices", "/class", "/dmi", "/id", "/bus", "/kernel",
    "/udev", "/net", "/power", "/firmware"
]

def _passes_filters(real_path: str) -> bool:
    """Return True if path should be monitored, False if it should be ignored."""
    try:
        # Normalize and clean the path once
        real_path = os.path.realpath(real_path).rstrip("/")
    except Exception:
        return False

    # Must be under monitored directories
    if not any(real_path.startswith(d) for d in MONITORED_DIRS):
        return False

    # Ignore system-level or internal noise
    if any(seg in real_path for seg in SYSTEM_NOISE):
        return False
    if any(k in real_path for k in IGNORE_KEYWORDS):
        return False

    # Ignore directories (only files matter)
    try:
        if os.path.isdir(real_path):
            return False
    except PermissionError:
        return False

    # Skip common shell/config/history files
    skip_patterns = (
        ".bashrc", ".bash_profile", ".bash_logout", ".profile",
        ".python_history", ".command_log", ".lesshst", ".wget-hsts",
        ".Xauthority", ".pki", ".gnupg", ".ssh", ".history",
        ".local/share/recently-used.xbel", "VirtualBox VMs", "snapshots"
    )
    if any(seg in real_path for seg in skip_patterns):
        return False

    # Drop home root and tool self-noise
    user_home = os.path.expanduser("~")
    if real_path == user_home or real_path.rstrip("/") == os.path.dirname(user_home):
        return False
    if "/.pgadmin/" in real_path or "pgadmin" in real_path.lower():
        return False
    if any(seg in real_path for seg in ("/.nvm/", "nvm.sh", "/alias/", "/versions/", "/lts/", "/default")):
        return False
    if "UEBA_BACKEND" in real_path:
        return False

    # AppArmor / Snap / system binary paths
    if any(seg in real_path for seg in (
        "/apparmor", "/snap/", "snapd", "/.snap", "snap-confine",
        "/usr/", "/lib/", "/lib64/", "/sbin/", "/bin/",
        "/var/lib/snapd", "/var/cache/apparmor", "mnt/", "ns/", "hostfs/"
    )):
        return False

    return True


def _classify_event(rec):
    """Classify a complete audit record into (etype, path [, new_path])."""
    path = rec.get("path")
    if not path:
        return None

    sc = rec.get("syscall", "")
    success = rec.get("success", "yes")
    new_path = rec.get("new_path")
    flags = rec.get("flags", 0)

    # Ignore failed syscalls
    if success != "yes":
        return None

    # Direct syscall classification
    if sc in ("unlink", "unlinkat"):
        return ("deleted", path)
    if sc in ("rename", "renameat", "renameat2"):
        return ("renamed", path, new_path)
    if sc in ("truncate", "ftruncate", "write", "writev", "pwrite64"):
        return ("modified", path)

    # open/openat logic based on access flags
    if sc in ("open", "openat"):
        O_CREAT, O_TRUNC, O_APPEND = 0x40, 0x200, 0x400
        O_RDWR, O_WRONLY = 0x2, 0x1
        if flags & O_CREAT:
            return ("created", path)
        if flags & (O_TRUNC | O_APPEND | O_RDWR | O_WRONLY):
            return ("modified", path)
        return ("read", path)

    # Fallback based on PATH record
    nt = rec.get("nametype")
    if nt == "CREATE":
        return ("created", path)
    if nt == "DELETE":
        return ("deleted", path)

    return None

# ===== Stream Audit Log (Live) =====
def stream_audit_log():
    """Stream audit.log lines continuously with resilience to log rotation."""
    log_path = "/var/log/audit/audit.log"

    # Use 'tail -n0 -F' to follow from EOF (not replay old history)
    with subprocess.Popen(
        ["tail", "-n0", "-F", log_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,  # suppress "file replaced" spam
        text=True,
        bufsize=1  # line-buffered
    ) as proc:
        try:
            for line in proc.stdout:
                if line:
                    yield line.strip()
        except GeneratorExit:
            proc.terminate()
        except Exception as e:
            print(f"[WARN] stream_audit_log error: {e}")
            proc.terminate()


def parse_and_aggregate():
    """
    Tail audit.log, buffer lines per event, extract all PATH entries,
    classify once per complete event (EOE), and yield normalized events.
    """
    buffers = {}

    for line in stream_audit_log():
        if "msg=audit(" not in line:
            continue

        m = MSG_RE.search(line)
        if not m:
            continue
        ev_id = m.group(2)
        buf = buffers.setdefault(ev_id, {"paths": {}})

        parts = line.split()

        # --- PATH ---
        if "type=PATH" in line:
            name = next((p.split("=", 1)[1].strip('"') for p in parts if p.startswith("name=")), None)
            nt = next((p.split("=", 1)[1] for p in parts if p.startswith("nametype=")), None)
            if not name or name in ("/", ".", "(null)"):
                continue
            try:
                rp = os.path.realpath(name)
                buf["paths"][nt] = rp
            except Exception:
                continue

        # --- SYSCALL ---
        if "type=SYSCALL" in line:
            sc = next((p.split("=", 1)[1] for p in parts if p.startswith("syscall=")), "")
            arch = next((p.split("=", 1)[1] for p in parts if p.startswith("arch=")), "")
            sc = _normalize_syscall(sc, arch)
            a1 = next((p.split("=", 1)[1] for p in parts if p.startswith("a1=")), None)
            a2 = next((p.split("=", 1)[1] for p in parts if p.startswith("a2=")), None)
            succ = next((p.split("=", 1)[1] for p in parts if p.startswith("success=")), "yes")
            buf.update({"arch": arch, "syscall": sc, "a1": a1, "a2": a2, "success": succ})

        # --- End of Event (EOE) ---
        if "type=EOE" in line:
            rec = buf
            # pick main + new paths
            path = (
                rec["paths"].get("NORMAL")
                or rec["paths"].get("DELETE")
                or rec["paths"].get("RENAME_OLD")
                or rec["paths"].get("CREATE")
            )
            newp = rec["paths"].get("RENAME_NEW") or rec["paths"].get("CREATE")

            if path:
                rec["path"] = path
            if newp:
                rec["new_path"] = newp

            rec["flags"] = _get_flags(rec)
            result = _classify_event(rec)
            if result:
                target_path = result[1]
                if _passes_filters(target_path):
                    yield result

            # always cleanup to avoid buffer growth
            buffers.pop(ev_id, None)


def emit_close_event(path: str):
    """Send UDP event when a file is closed."""
    try:
        size = os.path.getsize(path) if os.path.exists(path) else 0
    except (OSError, PermissionError):
        size = 0

    event_info = {
        "Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS",
        "Event Sub Type": "FILE_CLOSED",
        "Event Details": f"File closed at {path} ({size} bytes) on host {hostname}",
        "Value": path,
    }

    metrics = {
        "timestamp": datetime.now().isoformat(),
        "hostname": hostname,
        "mac_address": mac_address,
        "username": USERNAME,
        "ip_addresses": (lan_ip, internet_ip),
        "directory": path,
        "event_type": "closed",
        "file_size_bytes": size,
    }

    event_data = {
        "timestamp": metrics["timestamp"],
        "username": metrics["username"],
        "event_info": event_info,
        "metrics": metrics,
        "topic": "sensitive-events",
    }

    try:
        sock.sendto(json.dumps(event_data).encode("utf-8"), (UDP_IP, UDP_PORT))
        print(f"[AUDITD→UDP] CLOSED {path} ({size} bytes)")
    except Exception as e:
        print(f"[WARN] Failed to emit close event for {path}: {e}")


def start_close_watcher():
    """Monitor close events via inotify for finer-grained file closure tracking."""
    inot = INotify()
    watch_mask = (
        flags.CLOSE_WRITE | flags.CLOSE_NOWRITE | flags.CREATE | flags.MOVED_TO | flags.ONLYDIR
    )
    wd_to_dir = {}

    def add_dir(d):
        """Add directory to inotify watch list if valid."""
        try:
            if not os.path.isdir(d):
                return
            if not any(d.startswith(m) for m in MONITORED_DIRS):
                return
            if d in wd_to_dir.values():
                return
            wd = inot.add_watch(d, watch_mask)
            wd_to_dir[wd] = d
        except (OSError, PermissionError):
            pass  # skip inaccessible directories silently

    # Add existing directories under all monitored roots
    for root in MONITORED_DIRS:
        for dirpath, dirnames, _ in os.walk(root):
            add_dir(dirpath)

    def loop():
        """Continuous inotify event loop."""
        while True:
            try:
                for event in inot.read(timeout=500):
                    base = wd_to_dir.get(event.wd, "")
                    name = event.name or ""
                    path = os.path.realpath(os.path.join(base, name)) if name else base

                    # If a new directory is created or moved into the tree, start watching it
                    if (event.mask & flags.CREATE and event.mask & flags.ISDIR) or (
                        event.mask & flags.MOVED_TO and event.mask & flags.ISDIR
                    ):
                        add_dir(path)
                        continue

                    # Emit close events for files
                    if event.mask & (flags.CLOSE_WRITE | flags.CLOSE_NOWRITE):
                        if _passes_filters(path):
                            emit_close_event(path)
            except Exception as e:
                print(f"[WARN] Inotify loop error: {e}")
                time.sleep(1)  # small backoff on error

    Thread(target=loop, daemon=True, name="CloseWatcher").start()
# ===== Main =====
def main():
    print("\033[1;92m!!!!!!!!! File System Monitoring via Auditd (Live) + Inotify (Close Events) Running !!!!!!\033[0m")
    print("Monitoring directories:")
    for d in MONITORED_DIRS:
        print(f"   {d}")
    time.sleep(1)

    # Start inotify-based CLOSE watcher
    start_close_watcher()

    try:
        # Process auditd-based events
        for event in parse_and_aggregate():
            if not event:
                continue

            # Unpack events
            if len(event) == 3:
                etype, old_path, new_path = event
            else:
                etype, old_path = event
                new_path = None

            # Debounce duplicate events
            now = time.time()
            last = LAST_EVENT.get(old_path)
            if last and (now - last < 1.0):
                continue
            LAST_EVENT[old_path] = now

            # Safely determine file size (account for rename/move)
            try:
                if os.path.exists(old_path):
                    file_size = os.path.getsize(old_path)
                elif new_path and os.path.exists(new_path):
                    file_size = os.path.getsize(new_path)
                else:
                    file_size = 0
            except (OSError, PermissionError):
                file_size = 0

            # Determine final path
            target_path = new_path if new_path else old_path

            # Build event payload
            event_info = {
                "Event Type": "FILE_AND_OBJECT_ACCESS_EVENTS",
                "Event Sub Type": f"FILE_{etype.upper()}",
                "Event Details": f"File {etype} at {target_path} ({file_size} bytes) on host {hostname}",
                "Value": target_path
            }

            metrics = {
                "timestamp": datetime.now().isoformat(),
                "hostname": hostname,
                "mac_address": mac_address,
                "username": USERNAME,
                "ip_addresses": (lan_ip, internet_ip),
                "directory": target_path,
                "event_type": etype,
                "file_size_bytes": file_size
            }

            event_data = {
                "timestamp": metrics["timestamp"],
                "username": metrics["username"],
                "event_info": event_info,
                "metrics": metrics,
                "topic": "sensitive-events"
            }

            # Send event over UDP safely
            try:
                sock.sendto(json.dumps(event_data).encode("utf-8"), (UDP_IP, UDP_PORT))
                print(f"[AUDITD→UDP] {etype.upper()} {target_path} ({file_size} bytes)")
            except Exception as e:
                print(f"[WARN] Failed to send UDP event for {target_path}: {e}")

    except KeyboardInterrupt:
        print("\n[INFO] UEBA file monitoring stopped by user.")
    except Exception as e:
        print(f"[ERROR] Unexpected error in main loop: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
