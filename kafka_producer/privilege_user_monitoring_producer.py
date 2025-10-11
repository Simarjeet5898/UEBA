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
from collections import defaultdict
import binascii

CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH) as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
UDP_PORT = config["udp"]["server_port"]
POLL_INTERVAL = int(config.get("SCAN_INTERVAL", 5))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

AUTH_LOG = "/var/log/auth.log"
HOSTNAME = socket.gethostname()
DEVICE_MAC = ':'.join(f"{(uuid.getnode()>>i)&0xff:02x}" for i in range(40,-1,-8))

def get_privileged_users():
    users = {"root"}
    try:
        users |= set(grp.getgrnam("sudo").gr_mem)
        print(f"[DEBUG] Sudo group members: {users}")
    except KeyError:
        print("[DEBUG] 'sudo' group not found")
    for u in ("mysql", "postgres", "crl"):
        try:
            pwd.getpwnam(u)
            users.add(u)
            print(f"[DEBUG] Found user: {u}")
        except KeyError:
            print(f"[DEBUG] User '{u}' not found on system")
            continue
    print(f"[DEBUG] Final privileged users: {users}")
    return users

PRIV_USERS = get_privileged_users()
print(f"[DEBUG] Loaded privileged users: {PRIV_USERS}")

PRIV_UIDS = {pwd.getpwnam(u).pw_uid for u in PRIV_USERS}

auth_pos = 0
login_times = {u: None for u in PRIV_USERS}
logout_times = {u: None for u in PRIV_USERS}
prev_login = login_times.copy()
prev_logout = logout_times.copy()
last_cmd_time = {u: {} for u in PRIV_USERS}
COMMAND_COOLDOWN = 30

def get_user_type(u):
    if u == "root":
        return "root"
    if u in grp.getgrnam("sudo").gr_mem:
        return "privileged_user"
    if u in {"mysql", "postgres"}:
        return "db_owner"
    if u == "crl":
        return "monitored_user"
    return "unknown"


def init_positions():
    global auth_pos
    print(f"[DEBUG] Initializing file position for {AUTH_LOG}")
    try:
        with open(AUTH_LOG, 'rb') as f:
            f.seek(0, os.SEEK_END)
            auth_pos = f.tell()
        print(f"[DEBUG] Set initial auth_pos to end of file: {auth_pos}")
    except FileNotFoundError:
        print(f"[DEBUG] Log file {AUTH_LOG} not found — starting from position 0")
        auth_pos = 0



def read_new_lines(path, last_pos):
    try:
        with open(path, 'r') as f:
            f.seek(last_pos)
            lines = f.readlines()
            pos = f.tell()
            return lines, pos
    except FileNotFoundError:
        return [], last_pos

def update_session_times(lines):
    now = datetime.now().isoformat()
    for ln in lines:
        m1 = re.search(r"session opened for user (\w+)", ln)
        if m1:
            user = m1.group(1)
            if user in PRIV_USERS:
                login_times[user] = now
                logout_times[user] = None
        m2 = re.search(r"session closed for user (\w+)", ln)
        if m2:
            user = m2.group(1)
            if user in PRIV_USERS and login_times[user]:
                logout_times[user] = now

def collect_sudo_commands(lines):
    cmds = {u: [] for u in PRIV_USERS}
    for ln in lines:
        m_user = re.search(r"sudo: (\w+)", ln)
        m_cmd = re.search(r"COMMAND=(.*)", ln)
        if m_user and m_cmd:
            user = m_user.group(1).strip()
            if user in PRIV_USERS:
                cmds[user].append(m_cmd.group(1).strip())
    return cmds

def collector_metrics():
    global auth_pos

    print(f"[DEBUG] Reading new lines from {AUTH_LOG} starting at position {auth_pos}")
    auth_lines, auth_pos = read_new_lines(AUTH_LOG, auth_pos)
    print(f"[DEBUG] Read {len(auth_lines)} new lines, new position = {auth_pos}")

    if not auth_lines:
        print("[DEBUG] No new auth lines found")
        return None

    update_session_times(auth_lines)
    print(f"[DEBUG] Updated session times: {login_times}")

    sudo_cmds = collect_sudo_commands(auth_lines)
    print(f"[DEBUG] Collected sudo commands: {sudo_cmds}")

    now = datetime.now().isoformat()
    events = []

    for user in PRIV_USERS:
        current_cmds = sudo_cmds.get(user, [])
        if not current_cmds and not (login_times[user] or logout_times[user]):
            continue

        print(f"[DEBUG] Building event for user '{user}' — cmds={current_cmds}, "
              f"login={login_times[user]}, logout={logout_times[user]}")

        event = {
            "timestamp": now,
            "user": user,
            "user_type": get_user_type(user),
            "device_mac": DEVICE_MAC,
            "login_time": login_times[user],
            "logout_time": logout_times[user],
            "commands": current_cmds
        }
        events.append(event)

        prev_login[user] = login_times[user]
        prev_logout[user] = logout_times[user]

    print(f"[DEBUG] Total events generated: {len(events)}")
    return events if events else None




def main():
    logging.info("Auditd dependency skipped — using auth.log only for privileged activity tracking")

    init_positions()
    logging.info(f"Privileged User Monitor started | polling interval = {POLL_INTERVAL}s")

    while True:
        try:
            events = collector_metrics()
            if events:
                for evt in events:
                    try:
                        sock.sendto(json.dumps(evt).encode("utf-8"), (UDP_IP, UDP_PORT))
                    except Exception as send_err:
                        logging.error(f"UDP send failed: {send_err}")
                logging.info(f"Sent {len(events)} event(s) to {UDP_IP}:{UDP_PORT}")
            time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            logging.info("Privileged User Monitor stopped by user.")
            break
        except Exception as e:
            logging.error(f"Unexpected error in main loop: {e}")
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
