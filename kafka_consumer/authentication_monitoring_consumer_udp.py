import json
from datetime import timedelta
# from SIEM_connector import create_packet, load_config
from SIEM_connector import create_packet
import os
# import sys
from helper import store_anomaly_to_database_and_siem,store_siem_ready_packet
from collections import Counter
import ipaddress
from collections import defaultdict
import psycopg2
import time
from collections import deque
import socket 
from dataclasses import asdict
from helper import build_user_account_handling_packet,build_successful_login_after_login_failure_packet,build_login_failure_monitoring_packet

import logging
LOG = logging.getLogger("Authentication Monitoring Consumer")

# from udp_dispatcher import queues


CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]

# Auth consumer internal port
UDP_PORT = 6002  

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((UDP_IP, UDP_PORT))


FAILED_LOGIN_TIME_WINDOW = config["FAILED_LOGIN_TIME_WINDOW"]  # seconds
FAILED_LOGIN_THRESHOLD = config["FAILED_LOGIN_THRESHOLD"]     # how many failures trigger anomaly

FAILED_LOGIN_TRACKER = defaultdict(lambda: deque())  # key = username
FAILED_LOGIN_STATE   = defaultdict(int)              # total failed attempts per username

BRUTE_FORCE_ACTIVE = defaultdict(bool)

# key = hash of event, value = timestamp of last store
anomaly_cache = {}
CACHE_TTL = timedelta(seconds=10)


DB_CONFIG = {
    'host': config["local_db"]["host"],
    'user': config["local_db"]["user"],
    'password': config["local_db"]["password"],
    'dbname': config["local_db"]["dbname"]
}

HERE = os.path.dirname(os.path.abspath(__file__))
# REGISTRY_FILE = os.path.join(HERE, 'client_registry.json')

def init_db():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS authentication_log_ueba (
                id SERIAL PRIMARY KEY,
                timestamp TEXT,
                event_type TEXT,
                username TEXT,
                source_ip TEXT,
                source_hostname TEXT,
                mac_address TEXT,
                method TEXT,
                reason TEXT,
                creator TEXT,
                extra_data JSONB
            );
        """)
        conn.commit()
        cur.close()
        conn.close()
        # print("Authentication table created (if not exists).")
    except Exception as e:
        print(f"DB Init error: {e}")


def insert_authentication_event(event):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS authentication_log_ueba (
                id SERIAL PRIMARY KEY,
                timestamp TEXT,
                event_type TEXT,
                username TEXT,
                source_ip TEXT,
                source_hostname TEXT,
                mac_address TEXT,
                method TEXT,
                reason TEXT,
                creator TEXT,
                extra_data JSONB
            );
        """)
        cur.execute(
            """
            INSERT INTO authentication_log_ueba
            (timestamp, event_type, username, source_ip, source_hostname, mac_address, method, reason, creator, extra_data)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                event.get("timestamp"),
                event.get("event_type"),
                event.get("username"),
                event.get("source_ip"),
                event.get("source_hostname"),
                event.get("mac_address"),
                event.get("method"),
                event.get("reason"),
                event.get("creator"),
                json.dumps(event.get("extra_data", {}))
            )
        )
        conn.commit()
        cur.close()
        conn.close()
        print("Stored authentication event to Authentication Table.")
        LOG.info("Stored authentication event: %s", event.get("event_type"))
    except Exception as e:
        print(f"Authentication Table insert error: {e}")
        LOG.error("Authentication Table insert error: %s", e)



# Extract destinations from config
destinations = config["destinations"]

# Thresholds for anomaly detection
# earlier failed_logins": 0
THRESHOLDS = {
    # "failed_logins": 0,
    "failed_ssh_attempts": 2,
    "max_cron_jobs": 2,
    "sudo_failures": 0
}



# ─── UEBA_3 Non-AI thresholds ───────────────────────────────────────────
USER_FAIL_THRESHOLD        = 5    # failed attempts per username
IP_FAIL_THRESHOLD          = 10   # failed attempts per source IP
EXPIRED_CRED_THRESHOLD     = 1    # expired/disabled credential attempts
DICT_ATTACK_USER_THRESHOLD = 6    # distinct usernames in window


# Define normal working hours
NORMAL_HOURS_START = 9
NORMAL_HOURS_END = 17

# AUTHORIZED_SUBNET = "10.229.40.0/24"
AUTHORIZED_SUBNETS = [
    "10.229.40.0/24",
    "192.168.0.0/16"  # covers all 192.168.x.x IPs
]

# Anomaly Categories
ANOMALY_CATEGORIES = {

        "failed_login": {
        "Event Type": "AUTHENTICATION_EVENTS",
        "Event Sub Type": "FAILED_LOGIN",
        "Event Details": "Failed login attempt(s) detected"
    },
    "brute_force": {
        "Event Type": "AUTHENTICATION_EVENTS",
        "Event Sub Type": "BRUTE_FORCE",
        "Event Details": "Multiple failed login attempts – possible brute force"
    },

    "unusual_login_time": {
        "Event Type": "AUTHENTICATION_EVENTS",
        "Event Sub Type": "SUSPICIOUS_BEHAVIOUR",
        "Event Details": "Login Outside Working Hours"
    },
    "failed_ssh_attempts": {
        "Event Type": "AUTHENTICATION_EVENTS",
        "Event Sub Type": "FAILED_LOGIN",
        "Event Details": "Multiple Failed SSH Logins - Possible Brute Force Attack"
    },
    "unauthorized_remote_access": {
        "Event Type": "USER_ACTIVITY_EVENTS",
        "Event Sub Type": "UNUSUAL_IP_LOGIN_ATTEMPT",
        "Event Details": "SSH/RDP login from unrecognized IP"
    },
    "excessive_cron_jobs": {
        "Event Type": "USER_ACTIVITY_EVENTS",
        "Event Sub Type": "COMMAND_AND_SCRIPTING_INTERPRETER",
        "Event Details": "Unusual Increase in Cron Jobs"
    },
    "software_installed": {
        "Event Type": "USER_ACTIVITY_EVENTS",
        "Event Sub Type": "DEVICE_MALWARE_EVENTS",
        "Event Details": "Unusual Increase in Installed Software"
    },
    "unauthorized_usb_device": {
        "Event Type": "SYSTEM_ACTIVITY_EVENTS",
        "Event Sub Type": "UNUSUAL_USB_DETECTED",
        "Event Details": "Unauthorized USB Device Connected"
    },
    "sudo_failures": {
        "Event Type": "Privilege Escalation Attempt",
        "Event Sub Type": "Sudo Failures",
        "Event Details": "Multiple failed sudo attempts detected"
    },
    "privilege_esclation":{
        "Event Type": "SYSTEM_EVENTS",
        "Event Sub Type": "PRIVILEGE_ESCALATION",
        "Event Details": "Privilege_Attempt"
    },
    "reverse_shell":{
        "Event Type": "SECURITY_EVENTS",
        "Event Sub Type": "PHISHING_ATTEMPT",
        "Event Details": "suspicious reverse shell detection"
    }
}


REVERSE_SHELL_CACHE: dict[tuple, float] = {}
REVERSE_SHELL_TTL = 300          



def is_new_reverse_shell(evt: dict) -> bool:
    """
    True  → first sighting (or last sighting was ≥ TTL ago)
    False → duplicate we should drop.
    """
    key = (evt.get("user"), evt.get("remote"), evt.get("cmdline"))
    now = time.time()
    last = REVERSE_SHELL_CACHE.get(key, 0)
    if now - last >= REVERSE_SHELL_TTL:
        REVERSE_SHELL_CACHE[key] = now
        return True
    return False
# end here


def send_user_account_event_to_siem(event_type: str, username: str, metrics: dict, reason: str):
    """
    Common function to send USER_CREATION / USER_MODIFICATION / USER_DELETION
    events to SIEM.
    """

    # Extract IP
    remote_ip = metrics.get("remote_ip") or metrics.get("ip_addresses", ["Unknown"])
    if isinstance(remote_ip, list):
        source_ip = remote_ip[0] if remote_ip else "Unknown"
    elif isinstance(remote_ip, str):
        source_ip = remote_ip
    else:
        source_ip = "Unknown"

    # Extract hostname
    hostname = metrics.get("hostname")
    if isinstance(hostname, dict):
        hostname = hostname.get("name") or json.dumps(hostname)
    elif not isinstance(hostname, str):
        hostname = "Unknown"

    anomaly = {
        "timestamp": metrics.get("timestamp"),
        "event_type": "USER_ACTIVITY_EVENTS",
        "event_name": event_type,
        "username": username,
        "source_ip": str(source_ip),
        "source_hostname": hostname,
        "method": "USER_ACCOUNT_EVENT",
        "event_reason": reason,
        "account_action":event_type,
        # "reason": reason,
        "creator": metrics.get("creator", "System"),
        # "extra_data": {}
        "extra_data": json.dumps({})

    }

    store_anomaly_to_database_and_siem(anomaly)


def detect_login_anomalies(metrics):
    """Detect anomalies in login and system activity."""
    anomalies = []

    # ── Successful GUI login ──────────────────────────────
    login_time = metrics.get("login_time")
    if login_time:
        anomalies.append({
            "Event Type": "AUTHENTICATION_EVENTS",
            "Event Sub Type": "SUCCESSFUL_LOGIN",
            "Event Details": f"Local GUI login at {login_time}",
            "Value": login_time
        })

    # ── Remote IP anomalies ───────────────────────────────
    remote_ip_raw = metrics.get("remote_ip", [])
    if isinstance(remote_ip_raw, dict):
        remote_ip = list(remote_ip_raw.values())
    elif isinstance(remote_ip_raw, list):
        remote_ip = remote_ip_raw
    elif isinstance(remote_ip_raw, str):
        remote_ip = [remote_ip_raw]
    else:
        remote_ip = []

    if remote_ip:
        authorized_networks = [ipaddress.ip_network(subnet) for subnet in AUTHORIZED_SUBNETS]
        unauthorized = []
        for ip in remote_ip:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_loopback or ip_obj.is_private or any(ip_obj in net for net in authorized_networks)):
                    unauthorized.append(ip)
            except ValueError:
                unauthorized.append(ip)

        if unauthorized:
            info = ANOMALY_CATEGORIES["unauthorized_remote_access"]
            anomalies.append({
                "Event Type": info["Event Type"],
                "Event Sub Type": info["Event Sub Type"],
                "Event Details": info["Event Details"],
                "Value": unauthorized
            })

    cron_count = metrics.get("num_cron_jobs")
    if isinstance(cron_count, int) and cron_count > THRESHOLDS.get("max_cron_jobs", 10):
        info = ANOMALY_CATEGORIES["excessive_cron_jobs"]
        anomalies.append({
            "Event Type": info["Event Type"],
            "Event Sub Type": info["Event Sub Type"],
            "Event Details": info["Event Details"],
            "Value": cron_count
        })

    # ── Sudo failures ────────────────────────────────────
    sudo_data = metrics.get("sudo_failures")
    if sudo_data and isinstance(sudo_data, (list, tuple)) and len(sudo_data) == 3:
        sudo_time, sudo_failures, sudo_cmd = sudo_data
        if sudo_failures > THRESHOLDS.get("sudo_failures", 0):
            info = ANOMALY_CATEGORIES["sudo_failures"]
            anomalies.append({
                "Event Type": info["Event Type"],
                "Event Sub Type": info["Event Sub Type"],
                "Event Details": f"Excessive sudo failures: {sudo_cmd} at {sudo_time}",
                "Value": sudo_failures
            })

    # ── Privilege escalation attempts ─────────────────────
    for event in metrics.get("privilege_escalation_attempts", []) or []:
        info = ANOMALY_CATEGORIES["privilege_esclation"]
        anomalies.append({
            "Event Type": info["Event Type"],
            "Event Sub Type": info["Event Sub Type"],
            "Event Details": f"{info['Event Details']} by {event.get('user','?')} — "
                            f"Status: {event.get('status','?')} — "
                            f"Command: {event.get('command','?')}",
            "Value": event.get("time","unknown")
        })

    # ── Reverse shell detections ─────────────────────────
    for shell in metrics.get("reverse_shell_events", []) or []:
        if not is_new_reverse_shell(shell):
            continue
        info = ANOMALY_CATEGORIES["reverse_shell"]
        anomalies.append({
            "Event Type": info["Event Type"],
            "Event Sub Type": info["Event Sub Type"],
            "Event Details": (
                f"{info['Event Details']} by {shell.get('user','?')} "
                f"PID:{shell.get('pid','?')} Remote:{shell.get('remote','?')} "
                f"Cmd:{shell.get('cmdline','?')}"
            ),
            "Value": shell.get("timestamp","unknown")
        })

    # ── Failed logins & brute force detection ─────────────
    failed_logins = metrics.get("failed_logins") or 0
    if failed_logins > 0:
        mac = metrics.get("mac_address", "unknown")
        now = time.time()
        tracker = FAILED_LOGIN_TRACKER[mac]
        tracker.append(now)

        # Drop old timestamps outside the time window
        while tracker and (now - tracker[0] > FAILED_LOGIN_TIME_WINDOW):
            tracker.popleft()

        # If threshold exceeded, raise brute-force anomaly
        if len(tracker) >= FAILED_LOGIN_THRESHOLD:
            info = ANOMALY_CATEGORIES["brute_force"]
            anomalies.append({
                "Event Type": info["Event Type"],
                "Event Sub Type": info["Event Sub Type"],
                "Event Details": info["Event Details"],
                "Value": len(tracker)
            })

    # ── Per-user failed login velocity ────────────────────
    for user, cnt in (metrics.get("failed_logins_by_user") or {}).items():
        if cnt >= USER_FAIL_THRESHOLD:
            anomalies.append({
                "Event Type": "AUTHENTICATION_EVENTS",
                "Event Sub Type": "HIGH_VELOCITY_FAILED_LOGINS_BY_USER",
                "Event Details": f"{cnt} failed attempts for user {user}",
                "Value": {"username": user, "count": cnt}
            })

    # ── Per-IP failed login velocity ──────────────────────
    for ip, cnt in (metrics.get("failed_logins_by_ip") or {}).items():
        if cnt >= IP_FAIL_THRESHOLD:
            anomalies.append({
                "Event Type": "AUTHENTICATION_EVENTS",
                "Event Sub Type": "HIGH_VELOCITY_FAILED_LOGINS_BY_IP",
                "Event Details": f"{cnt} failed attempts from IP {ip}",
                "Value": {"ip_address": ip, "count": cnt}
            })

    # ── Expired/disabled credentials ─────────────────────
    expired_cnt = metrics.get("expired_credential_attempts", 0)
    if expired_cnt >= EXPIRED_CRED_THRESHOLD:
        anomalies.append({
            "Event Type": "AUTHENTICATION_EVENTS",
            "Event Sub Type": "EXPIRED_CREDENTIAL_ATTEMPTS",
            "Event Details": f"{expired_cnt} expired/disabled credential attempt(s)",
            "Value": expired_cnt
        })

    # ── Dictionary attack signatures ─────────────────────
    dict_sigs = metrics.get("dictionary_attack_signatures", [])
    if len(dict_sigs) >= DICT_ATTACK_USER_THRESHOLD:
        anomalies.append({
            "Event Type": "AUTHENTICATION_EVENTS",
            "Event Sub Type": "DICTIONARY_ATTACK_SIGNATURES",
            "Event Details": "Many distinct usernames in short window",
            "Value": dict_sigs
        })

    # ── SSH-specific failed attempts ─────────────────────
    raw = metrics.get("failed_ssh_attempts")
    if isinstance(raw, (list, tuple)):
        try:
            count = int(raw[0])
            ip_counts = Counter(raw[1])
        except Exception:
            count, ip_counts = 0, Counter()
    elif isinstance(raw, int):
        count, ip_counts = raw, Counter()
    else:
        count, ip_counts = 0, Counter()

    if count > THRESHOLDS.get("failed_ssh_attempts", 0):
        info = ANOMALY_CATEGORIES["failed_ssh_attempts"]
        offenders = [f"{ip}×{cnt}" for ip, cnt in ip_counts.most_common()]
        anomalies.append({
            "Event Type": info["Event Type"],
            "Event Sub Type": info["Event Sub Type"],
            "Event Details": f"{info['Event Details']} from {', '.join(offenders) if offenders else 'unknown'}",
            "Value": count
        })

    # ── Failed password change attempts ──────────────────
    failed_pw_changes = metrics.get("failed_password_changes", 0)
    users_pw_change = metrics.get("users_failed_password_change", [])
    if failed_pw_changes:
        anomalies.append({
            "Event Type": "AUTHENTICATION_EVENTS",
            "Event Sub Type": "PASSWORD_CHANGE_FAILURE",
            "Event Details": f"{failed_pw_changes} failed password change attempt(s)",
            "Value": users_pw_change or "unknown"
        })
        if failed_pw_changes >= 3:
            anomalies.append({
                "Event Type": "AUTHENTICATION_EVENTS",
                "Event Sub Type": "PASSWORD_CHANGE_BRUTE_FORCE",
                "Event Details": f"Possible brute-force: {failed_pw_changes} failed password changes within 5 min",
                "Value": users_pw_change or "unknown"
            })

    return anomalies




def normalize_event_fields(metrics: dict, username: str, event_type: str, reason: str, method="UNKNOWN", creator="System", extra_data=None):
    """Clean and standardize event fields for authentication_log_ueba."""
    remote_ip = metrics.get("remote_ip") or metrics.get("ip_addresses", ["Unknown"])
    if isinstance(remote_ip, list):
        source_ip = remote_ip[0] if remote_ip else "Unknown"
    elif isinstance(remote_ip, str):
        source_ip = remote_ip
    else:
        source_ip = "Unknown"

    hostname = metrics.get("hostname")
    if isinstance(hostname, dict):
        hostname = hostname.get("name") or json.dumps(hostname)
    elif not isinstance(hostname, str):
        hostname = "Unknown"

    return {
        "timestamp": metrics.get("timestamp"),
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "source_hostname": hostname,
        "method": method,
        "reason": reason,
        "creator": creator,
        "extra_data": extra_data or {}
    }


# def main():

def main(stop_event=None):
    print("\033[1;92m!!!!!!!!! Security Authentication Control Consumer Running (UDP) !!!!!!\033[0m")
    LOG.info("!!!!!!!!! Security Authentication Control Consumer Running (UDP) !!!!!!")

    init_db()
    # while True:
    while not (stop_event and stop_event.is_set()):
        try:
            data, addr = sock.recvfrom(65535)
            evt = json.loads(data.decode("utf-8"))
            LOG.info("[SAC received]: %s", list(evt.keys()))

            # Only process system-metrics events
            if evt.get("topic") != "system-metrics":
                continue

            metrics = evt

            # ------- New User Creation ---------
            if metrics.get("new_users"):
                for u in metrics["new_users"]:
                    remote_ip = metrics.get("remote_ip") or metrics.get("ip_addresses", ["Unknown"])
                    if isinstance(remote_ip, list):
                        source_ip = remote_ip[0] if remote_ip else "Unknown"
                    elif isinstance(remote_ip, str):
                        source_ip = remote_ip
                    else:
                        source_ip = "Unknown"

                    hostname = metrics.get("hostname")
                    if isinstance(hostname, dict):
                        hostname = hostname.get("name") or json.dumps(hostname)
                    elif not isinstance(hostname, str):
                        hostname = "Unknown"

                    print(f"[DEBUG] Consumed hostname: {hostname}")

                    insert_authentication_event({
                        "timestamp": metrics.get("timestamp"),
                        "event_type": "AUTHENTICATION_EVENTS",
                        "username": u,
                        "source_ip": str(source_ip),
                        "source_hostname": hostname,
                        "mac_address": metrics.get("mac_address"),
                        "method": "adduser",
                        "reason": f"User account '{u}' created",
                        "creator": metrics.get("creator", "System"),
                        "extra_data": {}
                    })

                    send_user_account_event_to_siem(
                        event_type="USER_CREATED",
                        username=u,
                        metrics=metrics,
                        reason=f"User account '{u}' created"
                    )
                    siem_packet = build_user_account_handling_packet({
                        "timestamp": metrics.get("timestamp"),
                        "event_type": "USER_ACTIVITY_EVENTS",
                        "event_name": "USER_CREATED",
                        "event_reason": f"User account '{u}' created",
                        "account_action": "USER_CREATED",
                        "log_text": f"User '{u}' created"
                    })
                    store_siem_ready_packet(asdict(siem_packet))


            if metrics.get("modified_users"):
                for u in metrics["modified_users"]:
                    remote_ip = metrics.get("remote_ip") or metrics.get("ip_addresses", ["Unknown"])
                    if isinstance(remote_ip, list):
                        source_ip = remote_ip[0] if remote_ip else "Unknown"
                    elif isinstance(remote_ip, str):
                        source_ip = remote_ip
                    else:
                        source_ip = "Unknown"

                    hostname = metrics.get("hostname")
                    if isinstance(hostname, dict):
                        hostname = hostname.get("name") or json.dumps(hostname)
                    elif not isinstance(hostname, str):
                        hostname = "Unknown"

                    insert_authentication_event({
                        "timestamp": metrics.get("timestamp"),
                        "event_type": "AUTHENTICATION_EVENTS",
                        "username": u,
                        "source_ip": source_ip,
                        "source_hostname": hostname,   # ✅ now always a string
                        "mac_address": metrics.get("mac_address"),
                        "method": "usermod",
                        "reason": f"User account '{u}' modified",
                        "creator": metrics.get("creator", "System"),
                        "extra_data": {}
                    })

                    send_user_account_event_to_siem(
                        event_type="USER_MODIFIED",
                        username=u,
                        metrics=metrics,
                        reason=f"User account '{u}' modified"
                    )

                    siem_packet = build_user_account_handling_packet({
                        "timestamp": metrics.get("timestamp"),
                        "event_type": "USER_ACTIVITY_EVENTS",
                        "event_name": "USER_MODIFIED",
                        "event_reason": f"User account '{u}' modified",
                        "account_action": "USER_MODIFIED",
                        "log_text": f"User '{u}' modified"
                    })
                    store_siem_ready_packet(asdict(siem_packet))


            if metrics.get("deleted_users"):
                for u in metrics["deleted_users"]:
                    remote_ip = metrics.get("remote_ip") or metrics.get("ip_addresses", ["Unknown"])
                    if isinstance(remote_ip, list):
                        source_ip = remote_ip[0] if remote_ip else "Unknown"
                    elif isinstance(remote_ip, str):
                        source_ip = remote_ip
                    else:
                        source_ip = "Unknown"

                    hostname = metrics.get("hostname")
                    if isinstance(hostname, dict):
                        hostname = hostname.get("name") or json.dumps(hostname)
                    elif not isinstance(hostname, str):
                        hostname = "Unknown"

                    insert_authentication_event({
                        "timestamp": metrics.get("timestamp"),
                        "event_type": "AUTHENTICATION_EVENTS",
                        "username": u,
                        "source_ip": source_ip,
                        "source_hostname": hostname,
                        "mac_address": metrics.get("mac_address"),  
                        "method": "userdel",
                        "reason": f"User account '{u}' deleted",
                        "creator": metrics.get("creator", "System"),
                        "extra_data": {}
                    })

                    send_user_account_event_to_siem(
                        event_type="USER_DELETED",
                        username=u,
                        metrics=metrics,
                        reason=f"User account '{u}' deleted"
                    )
                    siem_packet = build_user_account_handling_packet({
                        "timestamp": metrics.get("timestamp"),
                        "event_type": "USER_ACTIVITY_EVENTS",
                        "event_name": "USER_DELETED",
                        "event_reason": f"User account '{u}' deleted",
                        "account_action": "USER_DELETED",
                        "log_text": f"User '{u}' deleted"
                    })
                    store_siem_ready_packet(asdict(siem_packet))


            # ------- Successful login events (SSH/others) ---------
            if metrics.get("successful_logins"):
                for s in metrics["successful_logins"]:
                    username = s.get("username", metrics.get("username", "Unknown"))
                    method   = (s.get("method") or "UNKNOWN").upper()
                    ts       = s.get("timestamp") or metrics.get("timestamp")

                    # --- 1. If user was under brute-force → send recovery event ---
                    # if BRUTE_FORCE_ACTIVE[username] or FAILED_LOGIN_STATE[username] > 0:
                    if FAILED_LOGIN_STATE[username] > 0:
                        recovery_event = {
                            "timestamp": ts,
                            "event_type": "AUTHENTICATION_EVENTS",
                            "event_name": "SUCCESSFUL_LOGIN_AFTER_FAILED_LOGIN",
                            "username": username,
                            "source_ip": s.get("source_ip", "Unknown"),
                            "source_hostname": s.get("source_hostname") or metrics.get("hostname", "Unknown"),
                            "method": method,
                            "event_reason": f"Successful login after {FAILED_LOGIN_STATE[username]} failed attempts",
                            "creator": metrics.get("creator", "System"),
                            "extra_data": {}
                        }
                        store_anomaly_to_database_and_siem(recovery_event)

                        siem_packet = build_successful_login_after_login_failure_packet({
                            "timestamp": ts,
                            "event_type": "AUTHENTICATION_EVENTS",
                            "event_name": "SUCCESSFUL_LOGIN_AFTER_FAILED_LOGIN",
                            "event_reason": f"Successful login after {FAILED_LOGIN_STATE[username]} failed attempts",
                            "failure_count": FAILED_LOGIN_STATE[username],
                            "log_text": f"Successful login after {FAILED_LOGIN_STATE[username]} failures"
                        })
                        store_siem_ready_packet(asdict(siem_packet))

                    # --- 2. Insert normal successful login event ---
                    auth_event = {
                        "timestamp": ts,
                        "event_type": "AUTHENTICATION_EVENTS",
                        "username": username,
                        "source_ip": s.get("source_ip", "Unknown"),
                        "source_hostname": s.get("source_hostname") or metrics.get("hostname", "Unknown"),
                        "mac_address": metrics.get("mac_address"), 
                        "method": method,
                        "reason": f"Successful {method} authentication",
                        "creator": metrics.get("creator", "System"),
                        "extra_data": {}
                    }
                    insert_authentication_event(auth_event)

                    # --- 3. Reset brute-force state ---
                    BRUTE_FORCE_ACTIVE[username] = False
                    FAILED_LOGIN_STATE[username] = 0
                    FAILED_LOGIN_TRACKER[username].clear()

            # ------- Failed login events (SSH/others) ---------
            failed_users = metrics.get("failed_logins_by_user", {})
            # if not failed_users:
            #     continue

            failed_ips = metrics.get("failed_logins_by_ip", {})

            for username, new_count in failed_users.items():

                if new_count <= 0:
                    continue

                # ------------------------------------------------
                # 1. Metadata
                # ------------------------------------------------
                ts = metrics.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))
                hostname = metrics.get("hostname", "Unknown")
                hostname = hostname if isinstance(hostname, str) else "Unknown"

                source_ip = "Unknown"
                if failed_ips:
                    source_ip = list(failed_ips.keys())[0]

                # ------------------------------------------------
                # 2. PER-USER sliding 60-second window
                # ------------------------------------------------
                now = time.time()
                tracker = FAILED_LOGIN_TRACKER[username]

                # Insert new_count timestamps
                for _ in range(new_count):
                    tracker.append(now)

                # Remove old timestamps
                while tracker and (now - tracker[0] > FAILED_LOGIN_TIME_WINDOW):
                    tracker.popleft()

                total_for_user = len(tracker)
                FAILED_LOGIN_STATE[username] += new_count

                # ------------------------------------------------
                # 3. Insert FAILED_LOGIN event
                # ------------------------------------------------
                auth_event = {
                    "timestamp": ts,
                    "event_type": "AUTHENTICATION_EVENTS",
                    "event_name": "FAILED_LOGIN",
                    "username": username,
                    "source_ip": source_ip,
                    "source_hostname": hostname,
                    "mac_address": metrics.get("mac_address"), 
                    "method": "SSH",
                    "reason": f"{total_for_user} failed login attempt(s) for {username}",
                    "creator": metrics.get("creator", "System"),
                    "extra_data": {
                        "failed_logins_by_user": failed_users,
                        "failed_logins_by_ip": failed_ips,
                        "failed_ssh_attempts": metrics.get("failed_ssh_attempts", [])
                    }
                }
                insert_authentication_event(auth_event)

                # ------------------------------------------------
                # 4. BRUTE FORCE detection (exact multiples)
                # ------------------------------------------------
                if total_for_user > 0 and total_for_user % FAILED_LOGIN_THRESHOLD == 0:
                    anomaly = {
                        "timestamp": ts,
                        "event_type": "AUTHENTICATION_EVENTS",
                        "event_name": "SSH_BRUTE_FORCE_DETECTED",
                        "username": username,
                        "source_ip": source_ip,
                        "source_hostname": hostname,
                        "method": "SSH",
                        "event_reason": (
                            f"Brute force detected: {total_for_user} failed attempts "
                            f"within {FAILED_LOGIN_TIME_WINDOW} seconds"
                        ),
                        "creator": metrics.get("creator", "System"),
                        "extra_data": {}
                    }
                    store_anomaly_to_database_and_siem(anomaly)

                    # ---- SIEM Login Failure Monitoring Packet (UEBA_052) ----
                    siem_packet = build_login_failure_monitoring_packet({
                        "timestamp": ts,
                        "event_type": "AUTHENTICATION_EVENTS",
                        "event_name": "LOGIN_FAILURE_MONITORING",
                        "event_reason": (
                            f"{total_for_user} continuous failed login attempts detected"
                        ),
                        "failure_count": total_for_user,
                        "log_text": (
                            f"Login Failure Monitoring Triggered: {total_for_user} continuous failures"
                        )
                    })
                    store_siem_ready_packet(asdict(siem_packet))



            # ------- Failed Password Change ---------
            failed_pw_changes = metrics.get("failed_password_changes", 0)
            users_pw_change = metrics.get("users_failed_password_change", [])

            if failed_pw_changes > 0:
                print(f"[DEBUG] Detected {failed_pw_changes} failed password change(s) by users: {users_pw_change}")
                for username in users_pw_change or ["Unknown"]:
                    auth_event = normalize_event_fields(
                        metrics,
                        username=username,
                        event_type="PASSWORD_CHANGE_FAILURE",
                        reason=f"{failed_pw_changes} failed password change attempt(s)",
                        method="passwd command",
                        extra_data={
                            "users_failed": users_pw_change,
                            "total_failures": failed_pw_changes
                        }
                    )
                    insert_authentication_event(auth_event)

            # ------- Account Lockout Events (3.1 requirement) ---------
            lock_count   = metrics.get("account_lockouts", 0)
            locked_users = metrics.get("locked_users") or []

            if lock_count and locked_users:
                for username in locked_users:
                    # Per-user auth_log entry
                    reason = f"Account Lock out triggered"

                    final_evt = normalize_event_fields(
                        metrics,
                        username=username,
                        event_type="AUTHENTICATION_EVENTS",
                        reason=reason,
                        method="passwd",
                        extra_data={
                            "account_lockouts": lock_count,
                            "lock_source": "shadow"
                        }
                    )

                    insert_authentication_event(final_evt)

        except Exception as e:
            LOG.error(f"[SAC Consumer Error] {e}")



if __name__ == "__main__":
    main()


