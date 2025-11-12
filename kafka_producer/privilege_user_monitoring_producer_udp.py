import os
import sys
import json
import time
import uuid
import socket
import logging
from datetime import datetime
import pwd
import grp
import psycopg2 
from kafka_producer.new_log_monitor import get_command_executions


CONFIG_PATH = "/home/config.json"

with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
UDP_PORT = config["udp"]["server_port"]

# UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Basic metadata
hostname = os.uname().nodename
mac_address = ':'.join(f"{(uuid.getnode() >> i) & 0xff:02x}" for i in range(40, -1, -8))


STATE_DIR = "/var/lib/ueba"
os.makedirs(STATE_DIR, exist_ok=True)
STATE_FILE = os.path.join(STATE_DIR, "priv_users_state.json")



_last_seen_command_time = datetime.now()

def get_all_privileged_command_executions(priv_users):
    """
    Collect executed commands from ~/.bash_history of all privileged users.
    Only logs entries newer than _last_seen_command_time.
    """
    global _last_seen_command_time
    all_entries = []

    for uname in priv_users:
        try:
            user_info = pwd.getpwnam(uname)
            hist_file = os.path.join(user_info.pw_dir, ".bash_history")

            if not os.path.exists(hist_file):
                continue

            with open(hist_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            temp_timestamp = None
            for line in lines:
                line = line.strip()
                if not line:
                    continue

                if line.startswith("#"):
                    try:
                        ts = int(line[1:])
                        temp_timestamp = datetime.fromtimestamp(ts)
                    except Exception:
                        temp_timestamp = None
                else:
                    if temp_timestamp and temp_timestamp > _last_seen_command_time:
                        all_entries.append({
                            "timestamp": temp_timestamp.isoformat(),
                            "user_id": uname,
                            "command": line,
                            "source": "bash_history"
                        })
                        _last_seen_command_time = temp_timestamp
                    temp_timestamp = None

        except Exception as e:
            logging.error(f"Error reading history for user {uname}: {e}")

    if all_entries:
        logging.debug(f"Collected {len(all_entries)} commands from privileged users.")
    return all_entries


def _load_last_state():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"priv_users": [], "last_seen": None}

def _save_state(priv_users):
    payload = {"priv_users": priv_users, "last_seen": datetime.now().isoformat()}
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(payload, f)
    except Exception:
        logging.exception("Failed to save state")


IMPORTANT_FILES = [
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
]
SUDOERS_DIR = "/etc/sudoers.d"

def _read_prev_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _detect_privilege_config_change(prev_state):
    """
    Return (changed: bool, mt_state: dict)
    mt_state contains {'mtimes': {...}, 'sudoers_files': [...]}
    """
    prev_mtimes = prev_state.get("mtimes", {})
    new_mtimes = {}
    changed = False

    # check main files
    for path in IMPORTANT_FILES:
        try:
            m = os.path.getmtime(path)
        except Exception:
            m = None
        new_mtimes[path] = m
        if prev_mtimes.get(path) != m:
            changed = True

    # check /etc/sudoers.d files
    try:
        cur_files = sorted(os.listdir(SUDOERS_DIR))
    except Exception:
        cur_files = []

    prev_files = prev_state.get("sudoers_files", [])
    if cur_files != prev_files:
        changed = True

    for name in cur_files:
        p = os.path.join(SUDOERS_DIR, name)
        try:
            m = os.path.getmtime(p)
        except Exception:
            m = None
        new_mtimes[p] = m
        if prev_mtimes.get(p) != m:
            changed = True

    return changed, {"mtimes": new_mtimes, "sudoers_files": cur_files}


def get_system_privileged_users():
    """Return privileged users: root, sudo/wheel/docker users with valid shells, plus DB owner accounts."""
    privileged = set()

    valid_shells = ("/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/zsh", "/usr/bin/bash")

    DB_OWNER_ACCOUNTS = {
        "postgres",
        "mysql",
        "mariadb",
        "opensearch",
        "mongo",
        "mongodb",
        "redis",
        "influxdb",
        "neo4j"
    }

    # 1. UID=0 + valid login shell
    for user in pwd.getpwall():
        if user.pw_uid == 0 and user.pw_shell in valid_shells:
            privileged.add(user.pw_name)

    # 2. Privileged groups with valid shell
    privileged_groups = ["sudo", "wheel", "docker"]
    for group in privileged_groups:
        try:
            members = grp.getgrnam(group).gr_mem
            for m in members:
                try:
                    pw = pwd.getpwnam(m)
                    if pw.pw_shell in valid_shells:
                        privileged.add(m)
                except KeyError:
                    pass
        except KeyError:
            pass

    # 3. Database owner accounts (IGNORE SHELL)
    for user in pwd.getpwall():
        if user.pw_name in DB_OWNER_ACCOUNTS:
            privileged.add(user.pw_name)

    return privileged



def get_db_privileged_users():
    """Fetch privileged users stored by admin in DB."""
    try:
        conn = psycopg2.connect(
            dbname=config["db"]["dbname"],
            user=config["db"]["user"],
            password=config["db"]["password"],
            host=config["db"]["host"],
            port=config["db"]["port"]
        )
        cursor = conn.cursor()

        cursor.execute("""
            SELECT privileged_users 
            FROM privileged_user_config
            ORDER BY updated_at DESC
            LIMIT 1;
        """)

        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if not row or not row[0]:
            return set()

        return set(row[0]) 

    except Exception:
        return set()

def load_privileged_users():
    system_users = get_system_privileged_users()
    db_users     = get_db_privileged_users()
    merged_users = system_users | db_users

    metadata = {}

    for user in merged_users:

        if user in system_users and user in db_users:
            source = "privilege_config"
        elif user in system_users:
            source = "system"
        else:
            source = "db"


        if user == "root":
            acc_type = "root"

        elif user in system_users and user not in db_users:
            acc_type = "sudo_user"      # pure system detected

        elif user in db_users and user not in system_users:
            acc_type = "admin_defined"  # privileged only from DB

        elif user in system_users and user in db_users:
            acc_type = "merged"         # both system + DB defined

        else:
            acc_type = "unknown"

        metadata[user] = {
            "account_type": acc_type,
            "privilege_source": source
        }

    # combine username + MAC
    combined_set = {f"{user}@{mac_address}" for user in merged_users}

    return {
        "raw_users": sorted(list(merged_users)),
        "metadata": metadata,
        "unique_identifiers": sorted(list(combined_set))
    }


def get_system_context():
    """ Placeholder: return hostname/mac/timestamp. """
    return {
        "timestamp": datetime.now().isoformat(),
        "hostname": hostname,
        "mac": mac_address
    }


class PrivilegedEventMonitor:
    STATE_DIR = "/var/lib/ueba"
    STATE_FILE = os.path.join(STATE_DIR, "priv_users_state.json")

    def __init__(self):
        os.makedirs(self.STATE_DIR, exist_ok=True)

        loaded = load_privileged_users()
        self.priv_users = loaded["raw_users"]
        self.priv_meta  = loaded.get("metadata", {})
        self.unique_ids = loaded["unique_identifiers"]

        # load last snapshot
        self._last_users = self._load_last_users()

        print("\n[DEBUG] Raw privileged users:", self.priv_users)
        print("[DEBUG] Unique privileged IDs:", self.unique_ids)


    def _load_last_users(self):
        try:
            with open(self.STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return set(data.get("priv_users", []))
        except Exception:
            return set()


    def _save_last_users(self, users):
        try:
            with open(self.STATE_FILE, "w", encoding="utf-8") as f:
                json.dump({"priv_users": sorted(list(users)), "last_seen": datetime.now().isoformat()}, f)
        except Exception:
            logging.exception("Failed to persist priv users state")

    def poll_events(self):
        """
        Recompute privileged users, diff against last snapshot,
        detect config changes, and collect all command-execution events
        performed by any privileged users (reads each user's ~/.bash_history).
        """
        events = []

        # Load previous state
        prev_state = _read_prev_state()
        last_users_snapshot = set(prev_state.get("priv_users", []))

        # Recompute current privileged users
        loaded = load_privileged_users()
        current_users = set(loaded["raw_users"])

        # ---- First run: treat empty previous snapshot as baseline ----
        if not last_users_snapshot:
            last_users_snapshot = set(current_users)

        # Detect config file changes
        cfg_changed, mt_state = _detect_privilege_config_change(prev_state)
        if cfg_changed:
            ts = datetime.now().isoformat()
            events.append({
                "event_type": "privilege_config_changed",
                "timestamp": ts,
                "details": "Privilege-related config files changed (group/sudoers). Recomputing privileged set."
            })

        # Detect added/removed privileged accounts
        added   = sorted(list(current_users - last_users_snapshot))
        removed = sorted(list(last_users_snapshot - current_users))

        ts = datetime.now().isoformat()
        for u in added:
            events.append({
                "event_type": "privilege_added",
                "user": u,
                "timestamp": ts,
                "details": f"User {u} added to privileged set on host {hostname}"
            })

        for u in removed:
            events.append({
                "event_type": "privilege_removed",
                "user": u,
                "timestamp": ts,
                "details": f"User {u} removed from privileged set on host {hostname}"
            })

        # ---- Collect command executions from all privileged users ----
        try:
            cmd_entries = get_all_privileged_command_executions(current_users) or []
            print(f"[DEBUG] Collected {len(cmd_entries)} privileged command entries")
        except Exception as e:
            cmd_entries = []
            print(f"[ERROR] get_all_privileged_command_executions() failed: {e}")

        for ce in cmd_entries:
            ce_user = ce.get("user_id") or ce.get("user")
            if not ce_user:
                continue
            if ce_user in current_users:
                events.append({
                    "event_type": "command_executed",
                    "user": ce_user,
                    "timestamp": ce.get("timestamp", datetime.now().isoformat()),
                    "details": ce.get("command"),
                    "source": ce.get("source", "bash_history")
                })

        # ---- Persist merged state ----
        try:
            merged_state = prev_state.copy()
            merged_state.update(mt_state)
            merged_state["priv_users"] = sorted(list(current_users))
            merged_state["last_seen"] = datetime.now().isoformat()
            with open(self.STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(merged_state, f)
        except Exception:
            logging.exception("Failed to persist merged state")

        # ---- Update internal runtime state ----
        self._last_users = current_users
        self.priv_users  = sorted(list(current_users))
        self.priv_meta   = loaded.get("metadata", {})
        self.unique_ids  = loaded.get("unique_identifiers", [])

        print(f"[DEBUG] Updated privileged users: {self.priv_users}")
        print(f"[DEBUG] Total events this cycle: {len(events)}")
        return events



    def build_payload(self, events):
        return {
            "timestamp": datetime.now().isoformat(),
            "hostname": hostname,
            "mac_address": mac_address,
            "privileged_users": self.priv_users,
            "metadata": self.priv_meta,
            "events": events,
            "topic": "privileged-activity"
        }

    def send_payload(self, payload):
        try:
            sock.sendto(json.dumps(payload).encode("utf-8"), (UDP_IP, UDP_PORT))
        except Exception as e:
            logging.error(f"UDP send error: {e}")



def main():
    print("\033[92m=== Privileged User Monitoring Producer Started ===\033[0m")

    monitor = PrivilegedEventMonitor()

    while True:
        events = monitor.poll_events()     # no logic for now
        payload = monitor.build_payload(events)
        print(f"[DEBUG] Sending payload with {len(events)} events at {datetime.now().isoformat()}")

        monitor.send_payload(payload)
        time.sleep(5)



if __name__ == "__main__":
    main()
