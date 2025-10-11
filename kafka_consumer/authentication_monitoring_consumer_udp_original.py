import json
from datetime import timedelta
# from SIEM_connector import create_packet, load_config
from SIEM_connector import create_packet
import os
# import sys
from helper import store_anomaly_to_database_and_siem
from collections import Counter
import ipaddress
from collections import defaultdict
import psycopg2
import time
from collections import deque
import socket 
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


FAILED_LOGIN_TRACKER = defaultdict(lambda: deque())  # tracks timestamps of failed logins
FAILED_LOGIN_TIME_WINDOW = 60  # seconds
FAILED_LOGIN_THRESHOLD = 3     # how many failures trigger anomaly

FAILED_LOGIN_STATE = defaultdict(int)

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
REGISTRY_FILE = os.path.join(HERE, 'client_registry.json')

def insert_authentication_event(event):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS authentication_log (
                id SERIAL PRIMARY KEY,
                timestamp TEXT,
                event_type TEXT,
                username TEXT,
                source_ip TEXT,
                source_hostname TEXT,
                method TEXT,
                reason TEXT,
                creator TEXT,
                extra_data JSONB
            );
        """)
        cur.execute(
            """
            INSERT INTO authentication_log
            (timestamp, event_type, username, source_ip, source_hostname, method, reason, creator, extra_data)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                event.get("timestamp"),
                event.get("event_type"),
                event.get("username"),
                event.get("source_ip"),
                event.get("source_hostname"),
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


def load_registry():
    """Load the client registry from JSON file."""
    try:
        with open(REGISTRY_FILE, 'r') as f:
            registry = json.load(f)
        # print(f"Successfully loaded registry with {len(registry)} clients")
        return registry
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading registry: {e}")
        return {}

# project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
# sys.path.append(project_root)

# # Load configuration
# config_path = os.path.join(project_root, 'config', 'config.json')
# config = load_config(config_path)

# if not config:
#     print("Exiting due to configuration error.")
#     exit()

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



def detect_usb_anomalies(metrics):
    """Detect USB device anomalies using the registry."""
    anomalies = []
    
    mac = metrics.get('mac_address')
    if not mac:
        print("No MAC address in metrics")
        return anomalies
    
    # Load client registry
    registry = load_registry()
    
    # Get client data for this MAC
    client_data = registry.get(mac, {})
    
    if not client_data:
        # print(f"Warning: No registry entry found for MAC {mac}")
        # print(f"Available MACs in registry: {list(registry.keys())}")
        return anomalies
    
    # Get registered USB devices for this MAC
    registered_usb_devices = set()
    usb_devices_list = client_data.get('usb_devices', [])
    
    for device in usb_devices_list:
        if isinstance(device, dict) and 'device_id' in device:
            registered_usb_devices.add(device['device_id'])
    
    # Get current USB devices from metrics
    current_devices = metrics.get('devices', [])
    current_usb_devices = set()
    
    for device in current_devices:
        if isinstance(device, dict) and device.get('device_id'):
            current_usb_devices.add(device['device_id'])
    
    # Debug output
    print(f"MAC: {mac}")
    print(f"Registered USB devices: {registered_usb_devices}")
    print(f"Current USB devices: {current_usb_devices}")
    
    # Find new USB devices
    new_usb_devices = current_usb_devices - registered_usb_devices
    print(f"New USB devices detected: {new_usb_devices}")
    
    if new_usb_devices:
        # Get device details for the new devices
        new_device_details = []
        for device in current_devices:
            if device.get('device_id') in new_usb_devices:
                new_device_details.append(device)
        
        device_names = [d.get('name', d.get('device_id')) for d in new_device_details]
        
        event_info = ANOMALY_CATEGORIES["unauthorized_usb_device"]
        anomalies.append({
            "Event Type": event_info["Event Type"],
            "Event Sub Type": event_info["Event Sub Type"],
            "Event Details": f"{event_info['Event Details']}: {', '.join(device_names)}",
            "Value": list(new_usb_devices)
        })
        print(f"USB ANOMALY DETECTED: {device_names}")
    else:
        print("No new USB devices detected")
    
    return anomalies

#newly function added to remove duplicate reverse shell detection
REVERSE_SHELL_CACHE: dict[tuple, float] = {}
REVERSE_SHELL_TTL = 300          # seconds to suppress duplicates


#helper (place anywhere above detect_login_anomalies)
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

# def detect_login_anomalies(metrics):
#     """Detect anomalies in login and system activity."""
#     anomalies = []

#     # Successful GUI login
#     login_time = metrics.get("login_time")
#     if login_time:
#         anomalies.append({
#             "Event Type": "AUTHENTICATION_EVENTS",
#             "Event Sub Type": "SUCCESSFUL_LOGIN",
#             "Event Details": f"Local GUI login at {login_time}",
#             "Value": login_time
#         })

#     remote_ip_raw = metrics.get("remote_ip", [])
#     remote_ip = []

#     # Normalize to list of IP strings
#     if isinstance(remote_ip_raw, dict):
#         remote_ip = list(remote_ip_raw.values())
#     elif isinstance(remote_ip_raw, list):
#         remote_ip = remote_ip_raw
#     elif isinstance(remote_ip_raw, str):
#         remote_ip = [remote_ip_raw]

#     if remote_ip:
#         authorized = []
#         unauthorized = []
#         # authorized_network = ipaddress.ip_network(AUTHORIZED_SUBNETS)
#         authorized_network = [ipaddress.ip_network(subnet) for subnet in AUTHORIZED_SUBNETS]
#         for ip in remote_ip:
#             if not ip or ip == "Unknown":
#                 continue
#             try:
#                 ip_obj = ipaddress.ip_address(ip)
#                 # if ip_obj.is_loopback or ip_obj.is_private or (ip_obj in authorized_network):
#                 if ip_obj.is_loopback or ip_obj.is_private or any(ip_obj in net for net in authorized_network):
#                     authorized.append(ip)
#                 else:
#                     unauthorized.append(ip)
#             except ValueError:
#                 unauthorized.append(ip)

#         if unauthorized:
#             event_info = ANOMALY_CATEGORIES["unauthorized_remote_access"]
#             anomalies.append({
#                 "Event Type": event_info["Event Type"],
#                 "Event Sub Type": event_info["Event Sub Type"],
#                 "Event Details": event_info["Event Details"],
#                 "Value": unauthorized
#             })

#     # USB device anomalies
#     usb_anomalies = detect_usb_anomalies(metrics)
#     anomalies.extend(usb_anomalies)

#     # Excessive cron jobs
#     cron_count = metrics.get("num_cron_jobs")
#     if isinstance(cron_count, int) and cron_count > THRESHOLDS.get("max_cron_jobs", 10):
#         event_info = ANOMALY_CATEGORIES["excessive_cron_jobs"]
#         anomalies.append({
#             "Event Type": event_info["Event Type"],
#             "Event Sub Type": event_info["Event Sub Type"],
#             "Event Details": event_info["Event Details"],
#             "Value": cron_count
#         })

#     # Sudo failure anomalies
#     sudo_data = metrics.get("sudo_failures")
#     if sudo_data and isinstance(sudo_data, (list, tuple)) and len(sudo_data) == 3:
#         sudo_time, sudo_failures, sudo_cmd = sudo_data
#         if sudo_failures > THRESHOLDS.get("sudo_failures", 0):
#             event_info = ANOMALY_CATEGORIES["sudo_failures"]
#             anomalies.append({
#                 "Event Type": event_info["Event Type"],
#                 "Event Sub Type": event_info["Event Sub Type"],
#                 "Event Details": f"Excessive sudo failures: {sudo_cmd} at {sudo_time}",
#                 "Value": sudo_failures
#             })

#     # Check for unauthorized or suspicious privilege escalation attempts add by kamlesh and it is a new_sacc
#     escalation_events = metrics.get("privilege_escalation_attempts", [])
#     if escalation_events and isinstance(escalation_events, list):
#         for event in escalation_events:
#             user = event.get("user", "unknown")
#             time_str = event.get("time", "unknown")
#             command = event.get("command", "unknown")
#             status = event.get("status", "unknown")
#             ip_address = event.get("IP_addr","unknown")
    
#             event_info = ANOMALY_CATEGORIES["privilege_esclation"]
#             anomalies.append({
#                 "Event Type": event_info["Event Type"],
#                 "Event Sub Type": event_info["Event Sub Type"],
#                 "Event Details": f"{event_info['Event Details']} by {user} — Status: {status} — Command: {command}",
#                 "Value": time_str
#             })
            
#     reverse_shells = metrics.get("reverse_shell_events", [])
#     if reverse_shells and isinstance(reverse_shells, list):
#         for shell in reverse_shells:
#             if not is_new_reverse_shell(shell):
#                 continue                           # skip duplicates

#             info = ANOMALY_CATEGORIES["reverse_shell"]
#             anomalies.append({
#                 "Event Type":  info["Event Type"],
#                 "Event Sub Type": info["Event Sub Type"],
#                 "Event Details": (
#                     f"{info['Event Details']} by {shell.get('user','?')} "
#                     f"PID:{shell.get('pid','?')} "
#                     f"Remote:{shell.get('remote','?')} "
#                     f"Cmd:{shell.get('cmdline','?')}"
#                 ),
#                 "Value": shell.get("timestamp","unknown")
#             })

#     # Failed login and UEBA_3 non-AI checks
#         failed_logins = metrics.get("failed_logins") or 0
#         MIN_FAILED_LOGIN_THRESHOLD = 3  # adjust as needed

#         # if failed_logins > 0:
#         #     mac = metrics.get("mac_address", "unknown")
#         #     FAILED_LOGIN_STATE[mac] += failed_logins

#         #     if FAILED_LOGIN_STATE[mac] >= MIN_FAILED_LOGIN_THRESHOLD:
#         #         anomalies.append({
#         #             "Event Type": ANOMALY_CATEGORIES["failed_login"]["Event Type"],
#         #             "Event Sub Type": ANOMALY_CATEGORIES["failed_login"]["Event Sub Type"],
#         #             "Event Details": f"{FAILED_LOGIN_STATE[mac]} failed login attempt(s) detected",
#         #             "Value": FAILED_LOGIN_STATE[mac]
#         #         })
#         if failed_logins > 0:
#             mac = metrics.get("mac_address", "unknown")
#             now = time.time()

#             # Track timestamps in sliding window
#             tracker = FAILED_LOGIN_TRACKER[mac]
#             tracker.append(now)

#             # Remove old entries outside the time window
#             while tracker and (now - tracker[0] > FAILED_LOGIN_TIME_WINDOW):
#                 tracker.popleft()

#             # Only log to anomalies if threshold is crossed
#             if len(tracker) >= FAILED_LOGIN_THRESHOLD:
#                 anomalies.append({
#                     "Event Type": ANOMALY_CATEGORIES["brute_force"]["Event Type"],
#                     "Event Sub Type": ANOMALY_CATEGORIES["brute_force"]["Event Sub Type"],
#                     "Event Details": ANOMALY_CATEGORIES["brute_force"]["Event Details"],
#                     "Value": len(tracker)
#                 })


#         # Brute force detection & reset
#         if FAILED_LOGIN_STATE[mac] > 3:
#             anomalies.append({
#                 "Event Type": ANOMALY_CATEGORIES["brute_force"]["Event Type"],
#                 "Event Sub Type": ANOMALY_CATEGORIES["brute_force"]["Event Sub Type"],
#                 "Event Details": ANOMALY_CATEGORIES["brute_force"]["Event Details"],
#                 "Value": FAILED_LOGIN_STATE[mac]
#             })
#             FAILED_LOGIN_STATE[mac] = 0

#         # Per-user velocity
#         failed_by_user = metrics.get("failed_logins_by_user", {})
#         for user, cnt in failed_by_user.items():
#             if cnt >= USER_FAIL_THRESHOLD:
#                 anomalies.append({
#                     "Event Type": "AUTHENTICATION_EVENTS",
#                     "Event Sub Type": "HIGH_VELOCITY_FAILED_LOGINS_BY_USER",
#                     "Event Details": f"{cnt} failed attempts for user {user}",
#                     "Value": {"username": user, "count": cnt}
#                 })

#         # Per-IP velocity
#         failed_by_ip = metrics.get("failed_logins_by_ip", {})
#         for ip, cnt in failed_by_ip.items():
#             if cnt >= IP_FAIL_THRESHOLD:
#                 anomalies.append({
#                     "Event Type": "AUTHENTICATION_EVENTS",
#                     "Event Sub Type": "HIGH_VELOCITY_FAILED_LOGINS_BY_IP",
#                     "Event Details": f"{cnt} failed attempts from IP {ip}",
#                     "Value": {"ip_address": ip, "count": cnt}
#                 })

#         # Expired/disabled credentials
#         expired_cnt = metrics.get("expired_credential_attempts", 0)
#         if expired_cnt >= EXPIRED_CRED_THRESHOLD:
#             anomalies.append({
#                 "Event Type": "AUTHENTICATION_EVENTS",
#                 "Event Sub Type": "EXPIRED_CREDENTIAL_ATTEMPTS",
#                 "Event Details": f"{expired_cnt} expired/disabled credential attempt(s)",
#                 "Value": expired_cnt
#             })

#         # Dictionary-attack signatures
#         dict_sigs = metrics.get("dictionary_attack_signatures", [])
#         if len(dict_sigs) >= DICT_ATTACK_USER_THRESHOLD:
#             anomalies.append({
#                 "Event Type": "AUTHENTICATION_EVENTS",
#                 "Event Sub Type": "DICTIONARY_ATTACK_SIGNATURES",
#                 "Event Details": "Many distinct usernames in short window",
#                 "Value": dict_sigs
#             })

#     # SSH-specific failed attempts (unchanged)
#     raw = metrics.get("failed_ssh_attempts")
#     if raw is None:
#         count, ip_counts = 0, Counter()
#     elif isinstance(raw, (list, tuple)):
#         try:
#             count = int(raw[0])
#             ip_counts = Counter(raw[1])
#         except Exception:
#             count, ip_counts = 0, Counter()
#     else:
#         try:
#             count = int(raw)
#         except Exception:
#             count = 0
#         ip_counts = Counter()

#     if count > THRESHOLDS.get("failed_ssh_attempts", 0):
#         info = ANOMALY_CATEGORIES["failed_ssh_attempts"]
#         offenders = [f"{ip}×{cnt}" for ip, cnt in ip_counts.most_common()]
#         offenders_str = ", ".join(offenders) if offenders else "unknown"
#         anomalies.append({
#             "Event Type": info["Event Type"],
#             "Event Sub Type": info["Event Sub Type"],
#             "Event Details": f"{info['Event Details']} from {offenders_str}",
#             "Value": count
#         })
    
#     #### For Unsuccessful password change
#     failed_pw_changes = metrics.get("failed_password_changes", 0)
#     users_pw_change   = metrics.get("users_failed_password_change", [])

#     if failed_pw_changes:              # at least one attempt recorded
#         anomalies.append({
#             "Event Type": "AUTHENTICATION_EVENTS",
#             "Event Sub Type": "PASSWORD_CHANGE_FAILURE",
#             "Event Details": f"{failed_pw_changes} failed password change attempt(s)",
#             "Value": users_pw_change or "unknown"
#         })

#         # High-risk condition → escalate
#         if failed_pw_changes >= 3:     # adjust the threshold as you like
#             anomalies.append({
#                 "Event Type": "AUTHENTICATION_EVENTS",
#                 "Event Sub Type": "PASSWORD_CHANGE_BRUTE_FORCE",
#                 "Event Details": (
#                     f"Possible brute-force: {failed_pw_changes} failed password changes within 5 min"
#                 ),
#                 "Value": users_pw_change or "unknown"
#             })

#     return anomalies

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

    # ── USB device anomalies ──────────────────────────────
    anomalies.extend(detect_usb_anomalies(metrics))

    # ── Excessive cron jobs ───────────────────────────────
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
    """Clean and standardize event fields for authentication_log."""
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
    print("\033[1;92m!!!!!!!!! SAC Consumer Running (UDP) !!!!!!\033[0m")
    LOG.info("!!!!!!!!! SAC Consumer Running (UDP) !!!!!!")

    # while True:
    while not (stop_event and stop_event.is_set()):
        try:
            data, addr = sock.recvfrom(65535)
            evt = json.loads(data.decode("utf-8"))
            LOG.info("[SAC received]: %s", list(evt.keys()))

            # evt = queues["auth"].get()
            # print(f"[DEBUG] Authentication Consumer received raw event: {evt.get('topic')} | Keys: {list(evt.keys())}")


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
                        "event_type": "USER_CREATION",
                        "username": u,
                        "source_ip": str(source_ip),
                        "source_hostname": hostname,
                        "method": "adduser",
                        "reason": f"User account '{u}' created",
                        "creator": metrics.get("creator", "System"),
                        "extra_data": {}
                    })

            
            # ------- Successful login events (SSH/others) ---------
            if metrics.get("successful_logins"):
                for s in metrics["successful_logins"]:
                    username = s.get("username", metrics.get("username", "Unknown"))
                    method   = (s.get("method") or "UNKNOWN").upper()
                    ts       = s.get("timestamp") or metrics.get("timestamp")

                    auth_event = {
                        "timestamp": ts,
                        "event_type": "SUCCESSFUL_LOGIN",
                        "username": username,
                        "source_ip": s.get("source_ip", "Unknown"),
                        "source_hostname": s.get("source_hostname") or metrics.get("hostname", "Unknown"),
                        "method": method,
                        "reason": f"Successful {method} authentication",
                        "creator": metrics.get("creator", "System"),
                        "extra_data": {}
                    }
                    insert_authentication_event(auth_event)

            # # ------- Failed login events ---------
            # failed_logins = metrics.get("failed_logins", 0)
            # if failed_logins > 0:
            #     username = metrics.get("username", "Unknown")
            #     ts       = metrics.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))

            #     # Try to extract IP properly
            #     source_ip = "Unknown"
            #     if metrics.get("failed_logins_by_ip"):
            #         source_ip = list(metrics["failed_logins_by_ip"].keys())[0]

            #     hostname = metrics.get("hostname") or "Unknown"

            #     auth_event = {
            #         "timestamp": ts,
            #         "event_type": "FAILED_LOGIN",
            #         "username": username,
            #         "source_ip": source_ip,
            #         "source_hostname": hostname if isinstance(hostname, str) else "Unknown",
            #         "method": "SSH",
            #         "reason": f"{failed_logins} failed login attempt(s)",
            #         "creator": metrics.get("creator", "System"),
            #         "extra_data": {
            #             "failed_logins_by_user": metrics.get("failed_logins_by_user", {}),
            #             "failed_logins_by_ip": metrics.get("failed_logins_by_ip", {}),
            #             "failed_ssh_attempts": metrics.get("failed_ssh_attempts", [])
            #         }
            #     }
            #     insert_authentication_event(auth_event)
            # ------- Failed login events (track delta instead of total) ---------
            failed_logins_total = metrics.get("failed_logins", 0)
            if failed_logins_total > 0:
                mac      = metrics.get("mac_address", "unknown")
                username = metrics.get("username", "Unknown")
                ts       = metrics.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))

                # Compute how many NEW failures since last time
                prev_total = FAILED_LOGIN_STATE[mac]
                delta = failed_logins_total - prev_total
                FAILED_LOGIN_STATE[mac] = failed_logins_total

                if delta > 0:  # only log new failures
                    source_ip = "Unknown"
                    if metrics.get("failed_logins_by_ip"):
                        source_ip = list(metrics["failed_logins_by_ip"].keys())[0]

                    hostname = metrics.get("hostname") or "Unknown"

                    auth_event = {
                        "timestamp": ts,
                        "event_type": "FAILED_LOGIN",
                        "username": username,
                        "source_ip": source_ip,
                        "source_hostname": hostname if isinstance(hostname, str) else "Unknown",
                        "method": "SSH",
                        "reason": f"{delta} failed login attempt(s)",
                        "creator": metrics.get("creator", "System"),
                        "extra_data": {
                            "failed_logins_by_user": metrics.get("failed_logins_by_user", {}),
                            "failed_logins_by_ip": metrics.get("failed_logins_by_ip", {}),
                            "failed_ssh_attempts": metrics.get("failed_ssh_attempts", [])
                        }
                    }
                    insert_authentication_event(auth_event)

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

            # ------- Anomaly Detection ---------
            # anomalies = detect_login_anomalies(metrics)

            # if anomalies:
            #     alert_data = {
            #         "timestamp": metrics.get("timestamp", "N/A"),
            #         "username": metrics.get("username", "Unknown"),
            #         "mac_address": metrics.get("mac_address", "Unknown"),
            #         "ip_addresses": metrics.get("ip_addresses", "Unknown"),
            #         "anomalies": anomalies,
            #         "metrics": metrics
            #     }
            #     alert_json = json.dumps(alert_data)

            #     if isinstance(alert_data.get("logText"), dict):
            #         alert_data["logText"] = json.dumps(alert_data["logText"])

            #     feature_vectors = create_packet(alert_json)

            #     print("Attempting to store in POSTGRES...")
            #     LOG.info("Anomalies detected: %s", [a.get("Event Sub Type") for a in anomalies])
            #     LOG.debug("Anomalies detail: %s", anomalies)
            #     store_anomaly_to_database_and_siem(alert_json)
            anomalies = detect_login_anomalies(metrics)

            if anomalies:
                anomaly = {
                    # "eventId": str(uuid.uuid4()),  # unique ID
                    "username": metrics.get("username", "Unknown"),
                    "timestamp": metrics.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
                    "event_type": "AUTHENTICATION_EVENTS",
                    "event_name": "FAILED_LOGIN",
                    "severity": "ALERT",
                    "eventReason": f"Detected anomalies: {[a.get('Event Sub Type') for a in anomalies]}",
                    "deviceIp": (metrics.get("ip_addresses") or ["Unknown"])[0],
                    "deviceMacId": metrics.get("mac_address", "Unknown"),
                    "logText": json.dumps(metrics),  # stringified metrics (safe for DB/SIEM)
                    "riskScore": 10.0                # or your calculate_risk(anomalies)
                }

                print("Attempting to store in POSTGRES...")
                LOG.info("Anomalies detected: %s", [a.get("Event Sub Type") for a in anomalies])
                LOG.debug("Anomalies detail: %s", anomalies)

                store_anomaly_to_database_and_siem(anomaly)


        except Exception as e:
            LOG.error(f"[SAC Consumer Error] {e}")



if __name__ == "__main__":
    main()


