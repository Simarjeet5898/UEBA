import os
import time
import json
import socket
import re
import pwd
import grp
import uuid
import logging
from datetime import datetime
from kafka import KafkaProducer
from collections import defaultdict
import binascii

# ─── Configuration ─────────────────────────────────────────────────────────────
KAFKA_BROKER  = os.environ.get("KAFKA_BROKER", "localhost:9092")
KAFKA_TOPIC   = "privileged_user_metrics"
POLL_INTERVAL = 5
AUTH_LOG      = "/var/log/auth.log"
AUDIT_LOG     = "/var/log/audit/audit.log"

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
producer = KafkaProducer(
    bootstrap_servers=[KAFKA_BROKER],
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    compression_type="gzip",
    acks="all",
    linger_ms=200,
)

# ─── System Metadata ──────────────────────────────────────────────────────────
HOSTNAME = socket.gethostname()
DEVICE_MAC = ':'.join(f"{(uuid.getnode()>>i)&0xff:02x}" for i in range(40,-1,-8))
# iface    = os.popen("ip route | awk '/default/ {print $5}'").read().strip()
# try:
#     DEVICE_MAC = open(f"/sys/class/net/{iface}/address").read().strip()
# except Exception:
#     DEVICE_MAC = "unknown"
#     logging.warning("Could not determine device MAC address")

# ─── Privileged User Detection ─────────────────────────────────────────────────
def get_privileged_users():
    users = {"root"}
    try:
        users |= set(grp.getgrnam("sudo").gr_mem)
    except KeyError:
        logging.warning("Group 'sudo' not found")
    for db in ("mysql", "postgres"):
        try:
            pwd.getpwnam(db)
            users.add(db)
        except KeyError:
            pass
    try:
        pwd.getpwnam("crl")
        users.add("crl")
    except KeyError:
        logging.warning("User 'crl' not found")
    return users

PRIV_USERS = get_privileged_users()
PRIV_UIDS  = {pwd.getpwnam(u).pw_uid for u in PRIV_USERS}

# ─── Internal State ────────────────────────────────────────────────────────────
auth_pos     = 0
audit_pos    = 0
login_times  = {u: None for u in PRIV_USERS}
logout_times = {u: None for u in PRIV_USERS}
prev_login   = login_times.copy()
prev_logout  = logout_times.copy()
last_cmd_time = {u: {} for u in PRIV_USERS}
last_seen_files = {u: set() for u in PRIV_USERS}
COMMAND_COOLDOWN = 30  # seconds
# ─── Helpers ───────────────────────────────────────────────────────────────────
def get_user_type(u):
    if u == "root" or (u in PRIV_USERS - {"root"} and pwd.getpwnam(u).pw_uid == 0):
        return "root"
    if u in grp.getgrnam("sudo").gr_mem:
        return "privileged_user"
    if u in {"mysql", "postgres"}:
        return "db_owner"
    if u == "crl":
        return "monitored_user"
    return "unknown"

def init_positions():
    global auth_pos, audit_pos
    for path, var in ((AUTH_LOG, 'auth_pos'), (AUDIT_LOG, 'audit_pos')):
        try:
            with open(path, 'rb') as f:
                f.seek(0, os.SEEK_END)
                globals()[var] = f.tell()
        except FileNotFoundError:
            logging.error(f"Log file {path} not found")
            globals()[var] = 0

def read_new_lines(path, last_pos):
    try:
        with open(path, 'r') as f:
            f.seek(last_pos)
            lines = f.readlines()
            pos = f.tell()
            return lines, pos
    except FileNotFoundError:
        logging.error(f"Failed to read {path}")
        return [], last_pos

# ─── Audit Grouping ────────────────────────────────────────────────────────────
def group_audit_events(lines):
    grouped = defaultdict(list)
    for line in lines:
        m = re.search(r'audit\(([^)]+):(\d+)\)', line)
        if m:
            grouped[m.group(2)].append(line.strip())
    return grouped.values()

# ─── Log Processors ────────────────────────────────────────────────────────────
def update_session_times(lines):
    now = datetime.now().isoformat()
    for ln in lines:
        m1 = re.search(r"session opened for user (\w+)", ln)
        if m1:
            user = m1.group(1)
            if user in PRIV_USERS:
                if login_times[user] is None or logout_times[user] is not None:
                    login_times[user] = now
                    logout_times[user] = None

        m2 = re.search(r"session closed for user (\w+)", ln)
        if m2:
            user = m2.group(1)
            if user in PRIV_USERS and login_times[user] is not None:
                if login_times[user] != now:
                    logout_times[user] = now
                else:
                    # Ignore fake session (open/close at same time)
                    login_times[user] = None
                    logout_times[user] = None


def collect_sudo_commands(lines):
    cmds = {u: [] for u in PRIV_USERS}
    for ln in lines:
        m_user = re.search(r"sudo: (\w+)", ln)
        m_cmd  = re.search(r"COMMAND=(.*)", ln)
        if m_user and m_cmd:
            user = m_user.group(1).strip()
            if user in PRIV_USERS:
                cmd = m_cmd.group(1).strip()
                cmds[user].append(cmd)
    return cmds

def collect_exec_commands(groups):
    cmds = []
    for group in groups:
        if not any("type=EXECVE" in ln for ln in group):
            continue

        auid = None
        command = None
        for ln in group:
            if auid is None:
                m = re.search(r'auid=(\d+)', ln)
                if m:
                    auid = int(m.group(1))

            if command is None:
                m = re.search(r'argc=\d+ (a\d+="[^"]+"(?: a\d+="[^"]+")*)', ln)
                if m:
                    args = re.findall(r'a\d+="([^"]+)"', m.group(1))
                    command = ' '.join(args)

            if command is None:
                m = re.search(r'proctitle=([0-9a-f]+)', ln)
                if m:
                    try:
                        hex_str = m.group(1)
                        raw = binascii.unhexlify(hex_str)
                        command = raw.replace(b'\x00', b' ').decode().strip()
                    except Exception as e:
                        logging.warning(f"Proctitle decode failed: {e}")

            if command is None:
                m = re.search(r'comm="([^"]+)"', ln)
                if m:
                    command = m.group(1)

        # if auid is not None:
        #     try:
        #         user = pwd.getpwuid(auid).pw_name.strip()
        #         if user in PRIV_USERS:
        #             cmd = command or "unknown"
        #             cmds.append({"user": user, "command": cmd})
        #     except Exception as e:
        #         logging.error(f"Failed to resolve user for auid={auid}: {e}")
        if auid is not None:
            try:
                user = pwd.getpwuid(auid).pw_name.strip()
                if user in PRIV_USERS:
                    cmd = command or "unknown"
                    cmds.append({"user": user, "command": cmd})
            except KeyError:
                pass
            
        # Additional check: fallback to UID if AUID fails
        if auid is None:
            for ln in group:
                m = re.search(r'uid=(\d+)', ln)
                if m:
                    uid = int(m.group(1))
                    try:
                        user = pwd.getpwuid(uid).pw_name.strip()
                        if user in PRIV_USERS:
                            cmd = command or "unknown"
                            cmds.append({"user": user, "command": cmd})
                    except KeyError:
                        continue
                    
    return cmds

def collect_file_access(groups):
    exclude_prefixes = (
        "/proc/", "/sys/", "/run/", "/snap/", "/var/lib/", "/usr/lib/", "/lib/", "/lib64/",
        "/usr/bin/", "/bin/sh", "/usr/share/", "/bin/bash", "/home/crl/.config/",
        "/home/crl/.pgadmin/", "/home/crl/.local/", ".git/", "/etc/ssl/", "/home/crl/.cache/", "/tmp/","/home/crl/.vscode/"
    )
    files = {u: [] for u in PRIV_USERS}

    for group in groups:
        for ln in group:
            m_auid = re.search(r"auid=(\d+)", ln)
            m_uid  = re.search(r"uid=(\d+)", ln)
            m_fp   = re.search(r'name="([^"]+)"', ln)

            if not m_fp:
                continue

            path = m_fp.group(1)
            if any(path.startswith(p) for p in exclude_prefixes):
                continue
            if 'nametype=DIR' in ln or 'nametype="DIR"' in ln:
                continue
            # Try both auid and uid for mapping to privileged user
            uids_to_try = []
            if m_auid:
                uids_to_try.append(int(m_auid.group(1)))
            if m_uid:
                uids_to_try.append(int(m_uid.group(1)))

            for user_id in uids_to_try:
                if user_id in PRIV_UIDS:
                    try:
                        user = pwd.getpwuid(user_id).pw_name.strip()
                        if path not in files[user]:
                            files[user].append(path)
                        break  # Don't assign the same path to multiple users
                    except Exception as e:
                        logging.error(f"Failed to resolve user for uid={user_id}: {e}")
    return files

# ─── Collector ─────────────────────────────────────────────────────────────────
def collector_metrics():
    global auth_pos, audit_pos

    auth_lines, auth_pos = read_new_lines(AUTH_LOG, auth_pos)
    audit_lines_raw, audit_pos = read_new_lines(AUDIT_LOG, audit_pos)
    audit_groups = group_audit_events(audit_lines_raw)

    if not (auth_lines or audit_lines_raw):
        return None

    update_session_times(auth_lines)
    sudo_cmds = collect_sudo_commands(auth_lines)
    exec_events = collect_exec_commands(audit_groups)
    file_evts = collect_file_access(audit_groups)

    exec_map = {u: [] for u in PRIV_USERS}
    for ev in exec_events:
        exec_map[ev["user"]].append(ev["command"])

    now = datetime.now().isoformat()
    events = []

    for user in PRIV_USERS:
        current_cmds = sudo_cmds.get(user, []) + exec_map.get(user, [])
        files = file_evts.get(user, [])
        new_files = []
        for path in files:
            if path not in last_seen_files[user]:
                new_files.append(path)
                last_seen_files[user].add(path)
        # if login_times[user] == logout_times[user]:
        #     login_times[user] = None
        #     logout_times[user] = None
        #     continue  # skip this user’s event
        session_changed = (
            login_times[user] != prev_login[user] or logout_times[user] != prev_logout[user]
        )

        now_ts = time.time()
        unique_cmds = []
        for cmd in current_cmds:
            last_seen = last_cmd_time[user].get(cmd, 0)
            if now_ts - last_seen >= COMMAND_COOLDOWN:
                unique_cmds.append(cmd)
                last_cmd_time[user][cmd] = now_ts

        # If nothing new, skip
        if not (unique_cmds or new_files):
            continue
        
        event = {
            "timestamp":   now,
            "user":        user,
            "user_type":   get_user_type(user),
            "device_mac":  DEVICE_MAC,
            "login_time":  login_times[user],
            "logout_time": logout_times[user],
            "commands":    unique_cmds,
            "file_access": files
        }
        events.append(event)       
        prev_login[user] = login_times[user]
        prev_logout[user] = logout_times[user]
    return events if events else None

# ─── Main Loop ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if os.system("systemctl is-active --quiet auditd") != 0:
        logging.error("auditd is not running. Please start it with 'sudo systemctl start auditd'")
    
    audit_rule = '-a always,exit -F arch=b64 -S execve -k exec_priv'
    os.system(f"auditctl {audit_rule}")
    logging.info("Applied audit rule for execve tracking")
    
    init_positions()
    logging.info(f"Collector started, polling every {POLL_INTERVAL}s...")
    while True:
        data = collector_metrics()
        if data:
            try:
                producer.send(KAFKA_TOPIC, data)
                logging.info(f"Sent metrics: {json.dumps(data, indent=2)}")
            except Exception as e:
                logging.error(f"Kafka send error: {e}")
        time.sleep(POLL_INTERVAL)