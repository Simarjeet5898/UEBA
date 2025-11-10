import socket
import json
import time
import uuid
import signal
import os
import sys 
from datetime import datetime
import threading
import subprocess
from inotify_simple import INotify, flags

CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
UDP_PORT = config["udp"]["server_port"]

# === Use hostname + MAC as client_id ===
hostname = socket.gethostname()
mac_addr = hex(uuid.getnode())[2:]
CLIENT_ID = f"{hostname}_{mac_addr}"

# --- Heartbeat loop ---
def send_heartbeat(stop_event=None, interval=30):
    """Send active heartbeats until stop_event is set."""
    while not (stop_event and stop_event.is_set()):
        msg = {
            "type": "heartbeat",
            "client_id": CLIENT_ID,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "active"
        }
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(json.dumps(msg).encode(), (UDP_IP, UDP_PORT))
        except Exception as e:
            print(f"[UEBA Client] Failed to send heartbeat: {e}")
        time.sleep(interval)

# --- Shutdown message ---
def send_shutdown():
    """Send one last heartbeat marking client inactive before exit."""
    try:
        hostname = socket.gethostname()
        mac_addr = hex(uuid.getnode())[2:]
        client_id = f"{hostname}_{mac_addr}"

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            msg = {
                "type": "heartbeat",
                "client_id": client_id,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "inactive"
            }
            s.sendto(json.dumps(msg).encode(), (UDP_IP, UDP_PORT))
            print(f"[UEBA Client] Sent shutdown heartbeat for {client_id}")
    except Exception as e:
        print(f"[UEBA Client] Failed to send shutdown heartbeat: {e}")


# --- System Status Utilities ---

def get_boot_id():
    """Read the current Linux boot UUID from /proc/sys/kernel/random/boot_id"""
    try:
        with open("/proc/sys/kernel/random/boot_id", "r") as f:
            return f.read().strip()
    except Exception as e:
        print(f"[UEBA Client][DEBUG] Failed to read boot_id: {e}")
        return None


def get_uptime_seconds():
    """Read system uptime in seconds"""
    try:
        with open("/proc/uptime", "r") as f:
            return float(f.read().split()[0])
    except Exception as e:
        print(f"[UEBA Client][DEBUG] Failed to read uptime: {e}")
        return 0

# ---- Comprehensive configuration identification ----
EXTENSIONS = (
    ".conf", ".cfg", ".cnf", ".ini", ".yaml", ".yml", ".toml",
    ".policy", ".rules", ".properties", ".json",
    ".service", ".socket", ".target", ".timer", ".mount", ".path",
    ".link", ".network", ".netdev", ".xml",
)

EXACT_BASENAMES = (
    "sshd_config", "ssh_config", "fstab", "hosts", "hostname", "machine-id",
    "resolv.conf", "nsswitch.conf", "sudoers", "limits.conf", "login.defs",
    "environment", "journald.conf", "rsyslog.conf", "syslog-ng.conf",
    "ld.so.conf", "modprobe.conf", "nftables.conf", "iptables.rules",
    "docker-daemon.json", "daemon.json", "app.conf", "config",
)

DOTFILES = (
    ".bashrc", ".bash_profile", ".profile", ".zshrc", ".kshrc", ".cshrc", ".tcshrc",
    ".vimrc", ".gitconfig", ".npmrc", ".pylintrc", ".editorconfig",
    ".ssh/config", ".docker/config.json", ".aws/config",
)

SUBSTRINGS = (
    "/etc/", "/usr/lib/systemd/system/", "/etc/systemd/system/",
    "/etc/sysctl.d/", "/etc/modprobe.d/", "/etc/security/", "/etc/sudoers.d/",
    "/etc/ufw/", "/etc/firewalld/", "/etc/audit/", "/etc/selinux/", "/etc/apparmor.d/",
    "/etc/pam.d/", "/etc/default/", "/etc/sysconfig/", "/etc/modules-load.d/",
    "/etc/tmpfiles.d/", "/etc/rsyslog.d/", "/usr/lib/tmpfiles.d/", "/usr/lib/sysctl.d/",
    "/.config/", "/.ssh/config", "sysctl", "ufw", "firewalld", "nftables",
    "iptables", "audit", "apparmor", "selinux", "sudoers", "pam.d",
)

def looks_like_config(path: str) -> bool:
    base = os.path.basename(path)
    if base in EXACT_BASENAMES:
        return True
    if any(path.endswith(df) or base == df for df in DOTFILES):
        return True
    if any(base.endswith(ext) for ext in EXTENSIONS):
        return True
    if any(s in path for s in SUBSTRINGS):
        return True
    return False

def monitor_all_config_changes(stop_event=None):
    """
    Monitor filesystem for true configuration changes only.
    Excludes app caches, browser data, IDE state, office temp files, and runtime noise.
    Extremely exhaustive config detection — no legitimate config skipped.
    """

    EXCLUDE_PATHS = {
        "/proc", "/sys", "/dev", "/run", "/tmp", "/var/log", "/var/cache",
        "/var/tmp", "/var/spool", "/boot", "/lost+found", "/snap",
        "/media", "/mnt"
    }

    EXCLUDE_PATTERNS = (
        # generic user/runtime caches
        "/.cache", "/.local", "/.mozilla", "/.vscode", "/.pki",
        "/.config/pgadmin4", "/.config/BraveSoftware", "/snap/",
        "/.dbus", "/.npm", "/.cargo", "/.java", "/.gradle",
        "/Downloads", "/Videos", "/Pictures", "/Music",
        "/.steam", "/.wine", "/.android", "/.zoom", "/.nv",
        "/.terraform", "/.ansible", "/.thumbnails",
        "/__pycache__", "/.pytest_cache", "/.tox",
        "/Cache/", "/Cache_Data/", "/todelete_", "/session",
        "/Local State",

        # IDE / editor noise
        "/.config/Code/", "/.config/VSCode/", "/.vscode/",
        "/.config/libreoffice/", "/.config/jetbrains/", "/.idea/",
        "/History/", "/workspaceStorage/", "/backups/",

        # browser / app sandbox
        "/.config/google-chrome/", "/.config/chromium/",
        "/.config/BraveSoftware/", "/.config/discord/",
        "/.config/slack/", "/.config/zoomus/",
    )

    # ---- Comprehensive configuration identification ----
    EXTENSIONS = (
        ".conf", ".cfg", ".cnf", ".ini", ".yaml", ".yml", ".toml", ".json",
        ".policy", ".rules", ".properties", ".xml",
        ".service", ".socket", ".target", ".timer", ".mount", ".path",
        ".link", ".network", ".netdev",
    )

    EXACT_BASENAMES = (
        "sshd_config", "ssh_config", "fstab", "hosts", "hostname", "machine-id",
        "resolv.conf", "nsswitch.conf", "sudoers", "limits.conf", "login.defs",
        "environment", "journald.conf", "rsyslog.conf", "syslog-ng.conf",
        "ld.so.conf", "modprobe.conf", "nftables.conf", "iptables.rules",
        "docker-daemon.json", "daemon.json", "app.conf", "config",
    )

    DOTFILES = (
        ".bashrc", ".bash_profile", ".profile", ".zshrc", ".kshrc", ".cshrc", ".tcshrc",
        ".vimrc", ".gitconfig", ".npmrc", ".pylintrc", ".editorconfig",
        ".ssh/config", ".docker/config.json", ".aws/config",
    )

    SUBSTRINGS = (
        "/etc/", "/usr/lib/systemd/system/", "/etc/systemd/system/",
        "/etc/sysctl.d/", "/etc/modprobe.d/", "/etc/security/", "/etc/sudoers.d/",
        "/etc/ufw/", "/etc/firewalld/", "/etc/audit/", "/etc/selinux/", "/etc/apparmor.d/",
        "/etc/pam.d/", "/etc/default/", "/etc/sysconfig/", "/etc/modules-load.d/",
        "/etc/tmpfiles.d/", "/etc/rsyslog.d/", "/usr/lib/tmpfiles.d/", "/usr/lib/sysctl.d/",
        "/.config/", "/.ssh/config", "sysctl", "ufw", "firewalld", "nftables",
        "iptables", "audit", "apparmor", "selinux", "sudoers", "pam.d",
    )

    def looks_like_config(path: str) -> bool:
        base = os.path.basename(path)
        if base in EXACT_BASENAMES:
            return True
        if any(path.endswith(df) or base == df for df in DOTFILES):
            return True
        if any(base.endswith(ext) for ext in EXTENSIONS):
            return True
        if any(s in path for s in SUBSTRINGS):
            return True
        return False

    # ---- inotify setup ----
    inotify = INotify()
    mask = (
        flags.MODIFY | flags.CREATE | flags.DELETE |
        flags.MOVED_FROM | flags.MOVED_TO | flags.ATTRIB
    )

    wd_map = {}
    for root, dirs, _ in os.walk("/"):
        if any(root.startswith(x) for x in EXCLUDE_PATHS):
            continue
        try:
            wd = inotify.add_watch(root, mask)
            wd_map[wd] = root
        except Exception as e:
            print(f"[UEBA DEBUG] Cannot watch {root}: {e}")
            continue

    print("[UEBA Client][DEBUG] Config-only clean monitor initialized (kernel inotify).")

    last_event = {}
    debounce = 0.5  # seconds

    while not (stop_event and stop_event.is_set()):
        events = inotify.read(timeout=1000)
        for e in events:
            base = wd_map.get(e.wd, "")
            for flag in flags.from_mask(e.mask):
                if flag in (flags.Q_OVERFLOW,):
                    continue

                full_path = os.path.join(base, e.name)

                # skip excluded system and noise paths
                if any(full_path.startswith(x) for x in EXCLUDE_PATHS):
                    continue
                if any(p in full_path for p in EXCLUDE_PATTERNS):
                    continue

                # trigger only for genuine config-like paths
                if not looks_like_config(full_path):
                    continue

                short_path = full_path.replace("/", "_").strip("_")
                now = time.time()
                if short_path in last_event and (now - last_event[short_path]) < debounce:
                    continue
                last_event[short_path] = now

                try:
                    send_system_event(f"config_change_{short_path}")
                    print(f"[UEBA Client][DEBUG] Config change: {flag.name} → {full_path}")
                except Exception as ex:
                    print(f"[UEBA Client][ERROR] Config change send failed: {ex}")



def send_system_event(event_name, boot_time=None):
    """Send a system status message (startup/shutdown/abort)"""
    msg = {
        "type": "system_status",
        "event": event_name,
        "client_id": CLIENT_ID,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # Include real boot time if available
    if boot_time:
        msg["boot_time"] = boot_time.strftime("%Y-%m-%d %H:%M:%S")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(json.dumps(msg).encode(), (UDP_IP, UDP_PORT))
        # print(f"[UEBA Client][DEBUG] Sent system event: {event_name}")
    except Exception as e:
        print(f"[UEBA Client][DEBUG] Failed to send system event '{event_name}': {e}")



def monitor_subsystems(stop_event=None, interval=10):
    """Monitor all Linux services for start/stop/restart state changes."""
    last_state = {}

    print("[UEBA Client][DEBUG] Subsystem monitor initialized for ALL services")

    while not (stop_event and stop_event.is_set()):
        try:
            # Get all service names (remove trailing .service for readability)
            # services = os.popen("systemctl list-units --type=service --no-legend --no-pager | awk '{print $1}'").read().splitlines()
            services = os.popen("systemctl list-unit-files --type=service --no-legend --no-pager | awk '{print $1}'").read().splitlines()
            services = [s.strip().replace('.service', '') for s in services if s.strip()]

            for svc in services:
                try:
                    subprocess.run(["systemctl", "is-active", "--quiet", svc], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    active = True
                except subprocess.CalledProcessError:
                    active = False

                # Initialize baseline
                if svc not in last_state:
                    last_state[svc] = active
                    state_str = "active" if active else "inactive"

                    # Send the initial snapshot event
                    init_event = f"subsystem_init_{svc}_{state_str}"
                    send_system_event(init_event)
                    # print(f"[UEBA Client][DEBUG] Initial state: {svc} = {state_str} (sent to consumer)")
                    continue


                # Detect state change
                if last_state[svc] != active:
                    event = f"subsystem_startup_{svc}" if active else f"subsystem_shutdown_{svc}"
                    send_system_event(event)
                    last_state[svc] = active
                    # print(f"[UEBA Client][DEBUG] Detected state change → {svc} is now {'active' if active else 'inactive'}")

        except Exception as e:
            print(f"[UEBA Client][DEBUG] Subsystem monitor error: {e}")

        time.sleep(interval)



def monitor_config_changes(stop_event=None):
    """
    Monitor key Linux configuration directories using kernel-level inotify.
    Emits UEBA events for any configuration changes (modify/create/delete/move/attrib).
    """
    watch_dirs = [
        "/etc",
        "/usr/lib/systemd/system",
        "/etc/systemd/system",
        "/etc/network",
        "/etc/sysctl.d",
        "/etc/ufw",
        "/etc/ssh",
        "/etc/security"
    ]

    inotify = INotify()
    mask = (
        flags.MODIFY | flags.CREATE | flags.DELETE |
        flags.MOVED_FROM | flags.MOVED_TO | flags.ATTRIB
    )

    wd_map = {}
    for root_dir in watch_dirs:
        for root, dirs, _ in os.walk(root_dir):
            try:
                wd = inotify.add_watch(root, mask)
                wd_map[wd] = root
            except Exception as e:
                print(f"[UEBA Client][DEBUG] Cannot watch {root_dir}: {e}")
                continue

    # print("[UEBA Client][DEBUG] Config change monitor initialized...")

    last_event = {}
    debounce_interval = 0.5  # seconds

    while not (stop_event and stop_event.is_set()):
        events = inotify.read(timeout=1000)
        for e in events:
            base_dir = wd_map.get(e.wd, "")
            for flag in flags.from_mask(e.mask):
                if flag in (flags.Q_OVERFLOW,):
                    continue

                full_path = os.path.join(base_dir, e.name)
                short_path = full_path.replace("/", "_").strip("_")

                # Debounce duplicate rapid events
                now = time.time()
                if short_path in last_event and (now - last_event[short_path]) < debounce_interval:
                    continue
                last_event[short_path] = now

                # Send event
                try:
                    send_system_event(f"config_change_{short_path}")
                    # print(f"[UEBA Client][DEBUG] Config change detected: {flag.name} → {full_path}")
                except Exception as ex:
                    print(f"[UEBA Client][ERROR] Failed to send config change event: {ex}")




# ---- Logging Facility Monitoring (start, stop, alter, print, dump, delete, rename, overflow) ----

# candidates (will be checked for existence; nothing is assumed)
_LOG_CONFIG_FILES = [
    "/etc/systemd/journald.conf",
    "/etc/rsyslog.conf",
    "/etc/syslog-ng/syslog-ng.conf",
    "/etc/logrotate.conf",
    "/etc/audit/auditd.conf",
]
_LOG_CONFIG_DIRS = [
    "/etc/rsyslog.d",
    "/etc/syslog-ng",
    "/etc/logrotate.d",
    "/etc/audit",
    "/etc/systemd",                # journald.d snippets etc.
]
_LOG_DIRS = [
    "/tmp/fake_log",
    "/var/log",
    "/var/log/journal",
    "/run/log/journal",
    "/var/log/audit",
    "/var/lib/rsyslog",
    "/var/lib/syslog-ng",
]
# keywords to discover logging-related systemd units (service/socket/timer)
_LOG_UNIT_KEYWORDS = [
    "journal", "rsyslog", "syslog", "klogd", "logrotate", "audit",
    "coredump", "pstore", "gatewayd", "remote", "upload",
    "fluent", "filebeat", "promtail", "loki", "vector",
]

def _exists(paths):
    return [p for p in paths if os.path.exists(p)]

def _fs_pct_used(path):
    try:
        st = os.statvfs(path)
        if st.f_blocks == 0:
            return 0.0
        return (1 - (st.f_bavail / st.f_blocks)) * 100.0
    except Exception:
        return 0.0

def _discover_logging_units():
    """
    Discover logging-related units by keywords. Returns names without suffix (.service/.socket/.timer)
    """
    try:
        out = subprocess.check_output(
            ["systemctl", "list-unit-files", "--no-legend", "--no-pager",
             "--type=service", "--type=socket", "--type=timer"],
            stderr=subprocess.DEVNULL
        ).decode()
    except Exception:
        return []

    units = set()
    for line in out.splitlines():
        if not line.strip():
            continue
        name = line.split()[0]
        base = name.replace(".service", "").replace(".socket", "").replace(".timer", "")
        low = base.lower()
        if any(k in low for k in _LOG_UNIT_KEYWORDS):
            units.add(base)
    # print(f"[UEBA Client][DEBUG] Discovered logging units: {sorted(units)}")
    return sorted(units)

def system_logging_facility(stop_event=None,
                            service_scan_interval=5,
                            proc_scan_interval=10,
                            overflow_scan_interval=60,
                            debounce_seconds=0.5,
                            overflow_threshold_pct=75):
    """
    Comprehensive: detects start, stop, alter, print, dump, delete, rename, overflow
    for any present logging facilities/paths. Emits send_system_event("logging_<component>_<action>").
    """
    print("[UEBA Client][DEBUG] Logging facility monitor initialized.")

    # dynamic discovery (only track existing)
    cfg_files = _exists(_LOG_CONFIG_FILES)
    cfg_dirs  = _exists(_LOG_CONFIG_DIRS)
    log_dirs  = _exists(_LOG_DIRS) or ["/var/log"]  # ensure we have at least /var/log
    units     = _discover_logging_units()

    # ---- service start/stop ----
    last_state = {}

    # ---- file watchers (configs + logs) ----
    inotify = INotify()
    mask = flags.MODIFY | flags.CREATE | flags.DELETE | flags.MOVED_FROM | flags.MOVED_TO | flags.ATTRIB
    wd_map = {}

    def _watch_dir_recursively(root):
        for r, dnames, _ in os.walk(root):
            try:
                wd = inotify.add_watch(r, mask)
                wd_map[wd] = r
            except Exception:
                continue

    for d in cfg_dirs + log_dirs:
        if os.path.isdir(d):
            _watch_dir_recursively(d)
        elif os.path.isfile(d):
            parent = os.path.dirname(d) or "/"
            try:
                wd = inotify.add_watch(parent, mask)
                wd_map[wd] = parent
            except Exception:
                pass

    # quick membership checks
    cfg_roots = tuple(set(cfg_dirs + [os.path.dirname(p) for p in cfg_files]))
    log_roots = tuple(set(log_dirs))

    last_emit = {}  # (key)->timestamp for debounce

    def _debounced(key, window=debounce_seconds):
        t = time.time()
        prev = last_emit.get(key, 0)
        if (t - prev) < window:
            return True
        last_emit[key] = t
        return False

    # ---- threads ----
    def t_services():
        while not (stop_event and stop_event.is_set()):
            # refresh discovery occasionally (cheap enough to do every pass for simplicity)
            current_units = _discover_logging_units() or units
            for name in current_units:
                try:
                    rc = subprocess.call(["systemctl", "is-active", "--quiet", name],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    active = (rc == 0)
                except Exception:
                    active = False
                if name not in last_state:
                    last_state[name] = active
                    continue
                if last_state[name] != active:
                    action = "start" if active else "stop"
                    send_system_event(f"logging_{name}_{action}")
                    print(f"[UEBA Client][DEBUG] Logging service change detected → {name} {action}")
                    last_state[name] = active
            time.sleep(service_scan_interval)

    rename_buf = {}
    def t_inotify():
        while not (stop_event and stop_event.is_set()):
            events = inotify.read(timeout=1000)
            for e in events:
                base = wd_map.get(e.wd, "")
                path = os.path.join(base, e.name)
                bname = os.path.basename(path)

                # classify space
                in_cfg_space = base.startswith(cfg_roots) or path in cfg_files
                in_log_space = base.startswith(log_roots)

                if in_cfg_space:
                    if (e.mask & flags.DELETE):
                        if not _debounced(("cfg_del", path)):
                            send_system_event(f"logging_config_delete_{bname}")
                    elif (e.mask & (flags.MOVED_FROM | flags.MOVED_TO)):
                        if not _debounced(("cfg_mv", path)):
                            send_system_event(f"logging_config_rename_{bname}")
                    else:
                        if not _debounced(("cfg_alter", path)):
                            send_system_event(f"logging_config_alter_{bname}")
                    continue

                if in_log_space:
                    if (e.mask & flags.DELETE):
                        if not _debounced(("log_del", path)):
                            send_system_event(f"logging_file_delete_{bname}")
                            # print(f"[UEBA Client][DEBUG] Log delete → {path}")  
                    elif (e.mask & (flags.MOVED_FROM | flags.MOVED_TO)):
                        # log rotation/rename
                        if not _debounced(("log_mv", path)):
                            send_system_event(f"logging_file_rename_{bname}")
                            # print(f"[UEBA Client][DEBUG] Log rename → {path}") 
                    elif (e.mask & (flags.MODIFY | flags.CREATE | flags.ATTRIB)):
                        if not _debounced(("log_alt", path)):
                            send_system_event(f"logging_file_alter_{bname}")
                            # print(f"[UEBA Client][DEBUG] Log alter → {path}")

    def t_print_dump():
        while not (stop_event and stop_event.is_set()):
            try:
                # scan /proc for running processes
                for pid in os.listdir("/proc"):
                    if not pid.isdigit():
                        continue

                    cmdline_path = os.path.join("/proc", pid, "cmdline")
                    try:
                        with open(cmdline_path, "rb") as f:
                            raw = f.read().replace(b"\x00", b" ").decode("utf-8", "ignore").strip()
                    except Exception:
                        continue

                    low = raw.lower()

                    # --- DEBUG visibility ---
                    if "journalctl" in low or "logrotate" in low:
                        print(f"[UEBA Client][DEBUG] t_print_dump detected process → {low}")

                    # --- journalctl detection ---
                    if "journalctl" in low:
                        # dump-type actions (rotate, vacuum, flush, relinquish)
                        if any(x in low for x in ("--vacuum", "--rotate", "--flush", "--relinquish-var")):
                            if not _debounced(("dump_journalctl", pid), window=2.0):
                                send_system_event("logging_dump_journalctl")
                        else:
                            if not _debounced(("print_journalctl", pid), window=2.0):
                                send_system_event("logging_print_journalctl")

                    # --- logrotate detection ---
                    elif "logrotate" in low:
                        if not _debounced(("dump_logrotate", pid), window=2.0):
                            send_system_event("logging_dump_logrotate")

            except Exception as e:
                print(f"[UEBA Client][DEBUG] t_print_dump error: {e}")

            time.sleep(proc_scan_interval)


    def t_overflow():
        # overflow if any log filesystem > threshold
        while not (stop_event and stop_event.is_set()):
            try:
                checked = set()
                for d in log_dirs:
                    if not os.path.exists(d):
                        continue
                    # check the mount that contains d (simple heuristic: walk up until root or device changes)
                    mp = d
                    try:
                        dev = os.stat(d).st_dev
                        while True:
                            parent = os.path.dirname(mp) or "/"
                            if parent == mp:
                                break
                            if os.stat(parent).st_dev != dev:
                                break
                            mp = parent
                    except Exception:
                        mp = d
                    if mp in checked:
                        continue
                    checked.add(mp)
                    pct = int(_fs_pct_used(mp))
                    # print(f"[UEBA Client][DEBUG] Overflow check: {mp} usage={pct}% (threshold={overflow_threshold_pct}%)")

                    if pct >= overflow_threshold_pct:
                        if not _debounced(("overflow", mp), window=30):
                            print(f"[UEBA Client][DEBUG] Logging overflow detected → {mp} ({pct}%)")
                            send_system_event(f"logging_overflow_{pct}pct_{mp.replace('/','_')}")
            except Exception:
                pass
            time.sleep(overflow_scan_interval)

    # launch threads
    ts = []
    for target in (t_services, t_inotify, t_print_dump, t_overflow):
        t = threading.Thread(target=target, daemon=True)
        t.start()
        ts.append(t)

    # block until stopped
    while not (stop_event and stop_event.is_set()):
        time.sleep(1)
    for t in ts:
        t.join(timeout=1)

# def system_logging_facility(stop_event=None,
#                             service_scan_interval=5,
#                             proc_scan_interval=10,
#                             overflow_scan_interval=60,
#                             debounce_seconds=0.5,
#                             overflow_threshold_pct=75):

#     print("[UEBA Client][DEBUG] Logging facility monitor initialized.")

#     # ------------------------------------------------------------------
#     # Discovery
#     # ------------------------------------------------------------------
#     cfg_files = _exists(_LOG_CONFIG_FILES)
#     cfg_dirs  = _exists(_LOG_CONFIG_DIRS)
#     log_dirs  = _exists(_LOG_DIRS) or ["/var/log"]
#     units     = _discover_logging_units()

#     last_state = {}

#     # ------------------------------------------------------------------
#     # Inotify watcher setup
#     # ------------------------------------------------------------------
#     inotify = INotify()
#     mask = (flags.MODIFY | flags.CREATE | flags.DELETE |
#             flags.MOVED_FROM | flags.MOVED_TO | flags.ATTRIB)

#     wd_map = {}

#     def _watch_recursively(root):
#         for r, dirs, _ in os.walk(root):
#             try:
#                 wd = inotify.add_watch(r, mask)
#                 wd_map[wd] = r
#             except Exception:
#                 continue

#     for d in cfg_dirs + log_dirs:
#         if os.path.isdir(d):
#             _watch_recursively(d)
#         elif os.path.isfile(d):
#             parent = os.path.dirname(d)
#             try:
#                 wd = inotify.add_watch(parent, mask)
#                 wd_map[wd] = parent
#             except Exception:
#                 pass

#     cfg_roots = tuple(set(cfg_dirs + [os.path.dirname(p) for p in cfg_files]))
#     log_roots = tuple(set(log_dirs))

#     last_emit = {}

#     def _debounced(key, window=debounce_seconds):
#         t = time.time()
#         if key in last_emit and (t - last_emit[key]) < window:
#             return True
#         last_emit[key] = t
#         return False

#     # ------------------------------------------------------------------
#     # THREAD: Logging service start/stop
#     # ------------------------------------------------------------------
#     def t_services():
#         while not (stop_event and stop_event.is_set()):
#             current_units = _discover_logging_units() or units
#             for name in current_units:
#                 try:
#                     rc = subprocess.call(["systemctl", "is-active", "--quiet", name],
#                                          stdout=subprocess.DEVNULL,
#                                          stderr=subprocess.DEVNULL)
#                     active = (rc == 0)
#                 except Exception:
#                     active = False

#                 if name not in last_state:
#                     last_state[name] = active
#                     continue

#                 if last_state[name] != active:
#                     action = "start" if active else "stop"
#                     send_system_event(f"logging_{name}_{action}")
#                     print(f"[UEBA Client][DEBUG] Logging service change → {name} {action}")
#                     last_state[name] = active

#             time.sleep(service_scan_interval)

#     # ------------------------------------------------------------------
#     # THREAD: Inotify Processing (Config + Logging paths)
#     # ------------------------------------------------------------------
#     rename_buf = {}   # (base_dir, cookie) → old_name

#     def t_inotify():
#         while not (stop_event and stop_event.is_set()):
#             events = inotify.read(timeout=1000)
#             for e in events:
#                 base = wd_map.get(e.wd, "")
#                 path = os.path.join(base, e.name)
#                 bname = os.path.basename(path)

#                 in_cfg_space = base.startswith(cfg_roots) or path in cfg_files
#                 in_log_space = base.startswith(log_roots)

#                 # -----------------------
#                 # CONFIG SPACE EVENTS
#                 # -----------------------
#                 if in_cfg_space:
#                     if e.mask & flags.DELETE:
#                         if not _debounced(("cfg_del", path)):
#                             send_system_event(f"logging_config_delete_{bname}")

#                     elif e.mask & flags.MOVED_FROM:
#                         rename_buf[(base, e.cookie)] = bname

#                     elif e.mask & flags.MOVED_TO:
#                         old = rename_buf.pop((base, e.cookie), None)
#                         if old:
#                             if not _debounced(("cfg_rename", base, old, bname)):
#                                 send_system_event(f"logging_config_rename_{old}_to_{bname}")
#                         else:
#                             if not _debounced(("cfg_move_to", base, bname)):
#                                 send_system_event(f"logging_config_moved_to_{bname}")

#                     else:
#                         if not _debounced(("cfg_alter", path)):
#                             send_system_event(f"logging_config_alter_{bname}")
#                     continue

#                 # -----------------------
#                 # LOG FILE SPACE EVENTS
#                 # -----------------------
#                 if in_log_space:

#                     # DELETE
#                     if e.mask & flags.DELETE:
#                         if not _debounced(("log_del", path)):
#                             send_system_event(f"logging_file_delete_{bname}")
#                         continue

#                     # TRUE RENAME (same dir)
#                     if e.mask & flags.MOVED_FROM:
#                         rename_buf[(base, e.cookie)] = bname
#                         continue

#                     if e.mask & flags.MOVED_TO:
#                         old = rename_buf.pop((base, e.cookie), None)
#                         if old:
#                             # same directory rename
#                             if not _debounced(("log_rename", base, old, bname)):
#                                 send_system_event(f"logging_file_rename_{old}_to_{bname}")
#                         else:
#                             # moved into this directory
#                             if not _debounced(("log_move_to", base, bname)):
#                                 send_system_event(f"logging_file_moved_to_{bname}")
#                         continue

#                     # ALTER/CREATE/ATTRIB
#                     if e.mask & (flags.MODIFY | flags.CREATE | flags.ATTRIB):
#                         if not _debounced(("log_alter", path)):
#                             send_system_event(f"logging_file_alter_{bname}")
#                         continue

#     # ------------------------------------------------------------------
#     # THREAD: journalctl/logrotate print/dump detection
#     # ------------------------------------------------------------------
#     def t_print_dump():
#         while not (stop_event and stop_event.is_set()):
#             try:
#                 for pid in os.listdir("/proc"):
#                     if not pid.isdigit():
#                         continue

#                     cmdline = f"/proc/{pid}/cmdline"
#                     try:
#                         with open(cmdline, "rb") as f:
#                             raw = f.read().replace(b"\x00", b" ").decode().strip()
#                     except:
#                         continue

#                     low = raw.lower()

#                     if "journalctl" in low:
#                         if any(x in low for x in ("--vacuum", "--rotate", "--flush", "--relinquish-var")):
#                             if not _debounced(("dump_jctl", pid), window=2):
#                                 send_system_event("logging_dump_journalctl")
#                         else:
#                             if not _debounced(("print_jctl", pid), window=2):
#                                 send_system_event("logging_print_journalctl")

#                     elif "logrotate" in low:
#                         if not _debounced(("dump_lr", pid), window=2):
#                             send_system_event("logging_dump_logrotate")

#             except Exception as e:
#                 print(f"[UEBA Client][DEBUG] t_print_dump error: {e}")

#             time.sleep(proc_scan_interval)

#     # ------------------------------------------------------------------
#     # THREAD: Overflow Detection
#     # ------------------------------------------------------------------
#     def t_overflow():
#         while not (stop_event and stop_event.is_set()):
#             try:
#                 checked = set()
#                 for d in log_dirs:
#                     if not os.path.exists(d):
#                         continue

#                     mp = d
#                     try:
#                         dev = os.stat(d).st_dev
#                         while True:
#                             parent = os.path.dirname(mp) or "/"
#                             if parent == mp:
#                                 break
#                             if os.stat(parent).st_dev != dev:
#                                 break
#                             mp = parent
#                     except:
#                         mp = d

#                     if mp in checked:
#                         continue
#                     checked.add(mp)

#                     pct = int(_fs_pct_used(mp))
#                     if pct >= overflow_threshold_pct:
#                         if not _debounced(("overflow", mp), window=30):
#                             send_system_event(f"logging_overflow_{pct}pct_{mp.replace('/','_')}")

#             except:
#                 pass

#             time.sleep(overflow_scan_interval)

#     # ------------------------------------------------------------------
#     # Launch threads
#     # ------------------------------------------------------------------
#     threads = [
#         threading.Thread(target=t_services, daemon=True),
#         threading.Thread(target=t_inotify, daemon=True),
#         threading.Thread(target=t_print_dump, daemon=True),
#         threading.Thread(target=t_overflow, daemon=True),
#     ]

#     for t in threads:
#         t.start()

#     # Block
#     while not (stop_event and stop_event.is_set()):
#         time.sleep(1)

#     for t in threads:
#         t.join(timeout=1)



# --- Signal handler ---
stop_event = threading.Event()

def handle_exit(signum=None, frame=None, exit_after=True):
    print(f"\n[UEBA Client] Signal {signum} received, shutting down...")

    # --- SYSTEM SHUTDOWN EVENT ---
    send_system_event("system_shutdown")

    stop_event.set()
    send_shutdown()
    time.sleep(1)
    if exit_after:
        sys.exit(0)



# Trap signals
signal.signal(signal.SIGINT, handle_exit)   # Ctrl+C
signal.signal(signal.SIGTERM, handle_exit)  # kill
try:
    signal.signal(signal.SIGTSTP, handle_exit)  # Ctrl+Z
except AttributeError:
    pass


def main():
    # print(f"[UEBA Client] Heartbeat producer started for {CLIENT_ID} ...")
    print("\033[1;32m  !!!!!!!!!!!Heartbeat + System Status Producer started (UDP)!!!!!!!!!!!!!!\033[0m")

    # t1 = threading.Thread(target=send_heartbeat, args=(stop_event,))
    # t2 = threading.Thread(target=monitor_subsystems, args=(stop_event,))
    # t3 = threading.Thread(target=monitor_all_config_changes, args=(stop_event,))

    # t1.start(); t2.start(); t3.start()
    # t1.join(); t2.join(); t3.join()
    t1 = threading.Thread(target=send_heartbeat, args=(stop_event,))
    t2 = threading.Thread(target=monitor_subsystems, args=(stop_event,))
    t3 = threading.Thread(target=monitor_all_config_changes, args=(stop_event,))
    # NEW: logging facility monitor
    # t4 = threading.Thread(target=system_logging_facility, args=(stop_event,))
    t4 = threading.Thread(target=system_logging_facility, kwargs={"stop_event": stop_event, "proc_scan_interval": 1})

    t1.start(); t2.start(); t3.start(); t4.start()
    t1.join(); t2.join(); t3.join(); t4.join()


if __name__ == "__main__":
    print(f"[UEBA Client] Initializing system status check for {CLIENT_ID} ...")

    uptime = get_uptime_seconds()

    # Real system boot time (based on init process start)
    boot_time = datetime.fromtimestamp(os.path.getmtime("/proc/1"))
    send_system_event("system_startup", boot_time=boot_time)

    # --- SYSTEM ABORT / UNEXPECTED REBOOT DETECTION ---
    boot_file = "/tmp/.bootid_last"
    current_boot = get_boot_id()
    last_boot = None
    if os.path.exists(boot_file):
        with open(boot_file, "r") as f:
            last_boot = f.read().strip()

    # if previous boot_id exists and differs, previous shutdown missing => system abort
    if last_boot and current_boot and current_boot != last_boot:
        send_system_event("system_abort")

    # store current boot_id for next comparison
    try:
        with open(boot_file, "w") as f:
            f.write(current_boot or "")
    except Exception as e:
        print(f"[UEBA Client][DEBUG] Failed to write boot_id file: {e}")

    main()

