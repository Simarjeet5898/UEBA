# SIEM_connection.py
import os
import socket
import uuid
import json
import getpass
from datetime import datetime
# from datetime import time,datetime,timedelta, timezone
# import sys
import requests
# from collections import Counter
import logging
import psutil

CONFIG_PATH = os.environ.get("UEBA_CONFIG", "/home/config.json")

with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

if not config:
  print("Exiting due to configuration error.")
  exit()


# Extract configurations
# siem_api_url = config.get("siem_api_url")
siem_api_url = "https://httpbin.org/post"
destinations = config["destinations"]
device_type = config["device_type"]
source_id = config["source_id"]
dest_id = config["dest_id"]
msg_id = config["msg_id"]

mappings = config["mappings"]
# event_type_mapping = mappings["event_type"]
event_type_mapping = config["event_type"]
# event_subtype_mapping = mappings["event"]
event_subtype_mapping = config["event_name"]
device_tags_mapping = mappings["device_tags"]
linux_service_components_mapping = mappings["linux_service_components"]
severity_mapping = mappings["severity"]

# Get MAC Address
def get_mac_address():
  try:
      return ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8 * 6, 8)[::-1]])
  except Exception:
      return "00:00:00:00:00:00"

# Get Device IP
def get_device_ip():
  try:
      return socket.gethostbyname(socket.gethostname())
  except Exception:
      return "10.10.100.67"


def get_primary_ip():
    """Try to return the main outbound IP (LAN or WAN)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't send traffic, just forces routing decision
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass

    # fallback: check all interfaces for first non-loopback IPv4
    try:
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            for addr in addr_list:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    return addr.address
    except Exception:
        pass

    return "unknown"


# Generate Unique Event ID using UUID
def generate_event_id():
  return str(uuid.uuid4())

# Function to get the current user
def get_current_user():
  try:
      return getpass.getuser()
  except Exception:
      return "Unknown User"

def parse_timestamp(timestamp_str):
   """Parse timestamp string in ISO 8601 format."""
   try:
       dt = datetime.fromisoformat(timestamp_str)
       return dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second
   except ValueError as e:
       print(f"Error parsing timestamp: {e}")
       return 1970, 1, 1, 0, 0, 0

def create_packet(kafka_output):
    # Handle both dict and JSON string
    if isinstance(kafka_output, str):
        try:
            data = json.loads(kafka_output)
        except Exception as e:
            raise ValueError(f"Failed to parse kafka_output as JSON string: {e}")
    elif isinstance(kafka_output, dict):
        data = kafka_output
    else:
        raise ValueError(f"Unsupported type for kafka_output: {type(kafka_output)}")

    # print("[DEBUG] Using data keys:", data.keys())

    timestamp = data["timestamp"]
    year, month, date, hour, minute, second = parse_timestamp(timestamp)

    # Extract metrics with fallback to log_text
    metrics = data.get("metrics")
    if not metrics and "log_text" in data:
        try:
            metrics = json.loads(data["log_text"])
            # print("[DEBUG] Parsed metrics from log_text keys:", metrics.keys())
        except Exception as e:
            print("[DEBUG] Failed to parse log_text:", e)
            metrics = {}
    elif not metrics:
        metrics = {}
    if not metrics:
        metrics = data

    per_proc_mem = metrics.get("per_process_memory", [])
    log_text = json.dumps(metrics)

    USERNAME = data.get("user_id") or metrics.get("username") or "unknown"

    # --- System metrics ---
    cpu_usage = float(metrics.get("cpu_usage", 0))
    memory_usage = float(metrics.get("memory_usage", 0))
    disk_usage = float(metrics.get("disk_usage", 0))

    raw_temp = metrics.get("system_temperature")
    try:
        system_temp = float(raw_temp) if raw_temp is not None else 0.0
    except (TypeError, ValueError):
        system_temp = 0.0

    failed_logins = int(metrics.get("failed_logins") or 0)
    failed_ssh_tuple = metrics.get("failed_ssh_attempts", (0, {}))
    failed_ssh = failed_ssh_tuple[0] if isinstance(failed_ssh_tuple, tuple) else 0
    sudo_failures_tuple = metrics.get("sudo_failures", (None, 0, None))
    sudo_failures = sudo_failures_tuple[1] if isinstance(sudo_failures_tuple, tuple) else 0

    usb_mounts = metrics.get("usb_mounts", [])
    mac_address = metrics.get("mac_address", get_mac_address())
    ip_addresses = get_primary_ip()
    if isinstance(ip_addresses, (list, tuple)):
        ip_addresses = ip_addresses[0]

    # -------------------
    # Risk score calculation
    # -------------------
    base_risk = (
        cpu_usage * 0.2 +
        memory_usage * 0.2 +
        failed_logins * 10 +
        failed_ssh * 10
    )

    additional_risk = 0

    # Disk usage risk
    if disk_usage > 95: additional_risk += 15
    elif disk_usage > 90: additional_risk += 10
    elif disk_usage > 85: additional_risk += 5

    # Temperature risk
    if system_temp > 85: additional_risk += 10
    elif system_temp > 75: additional_risk += 5

    # USB devices risk
    if len(usb_mounts) > 0: additional_risk += len(usb_mounts) * 5

    # Sudo failures
    additional_risk += sudo_failures * 15

    # Encrypted files
    encrypted_files = data.get("encrypted_files", 0)
    if encrypted_files > 0:
        additional_risk += min(30, encrypted_files * 0.1)

    # ---- Authentication anomaly risk ----
    if metrics.get("event_type") in ("login", "logout"):
        additional_risk += 5  # baseline risk
        if metrics.get("auth_type") in ("remote", "ssh"):
            additional_risk += 10
        if "session_duration_seconds" in metrics:
            try:
                duration = int(metrics["session_duration_seconds"])
                if duration > 36000:   # >10h
                    additional_risk += 10
                if duration > 86400:   # >24h
                    additional_risk += 20
            except Exception:
                pass

    risk_score = min(100, int(base_risk + additional_risk))
    print(f"Calculated Risk Score: {risk_score}")
#     # -------------------
# # Risk score calculation (UEBA-based multi-factor model)
# # -------------------
#     risk_score = 0

#     # 1. Authentication anomalies
#     if metrics.get("failed_logins", 0) > 0:
#         risk_score += min(30, int(metrics["failed_logins"]) * 5)

#     failed_ssh_tuple = metrics.get("failed_ssh_attempts", (0, {}))
#     failed_ssh = failed_ssh_tuple[0] if isinstance(failed_ssh_tuple, tuple) else 0
#     if failed_ssh > 0:
#         risk_score += min(30, failed_ssh * 5)

#     if metrics.get("event_type") in ("login", "logout"):
#         # Off-hours login (baseline 9–18)
#         hour = datetime.now().hour
#         if not (9 <= hour <= 18):
#             risk_score += 10
#         # Remote/SSH access
#         if metrics.get("auth_type") in ("remote", "ssh"):
#             risk_score += 15
#         # Session duration anomalies
#         if "session_duration_seconds" in metrics:
#             try:
#                 dur = int(metrics["session_duration_seconds"])
#                 if dur > 86400:  # >24h
#                     risk_score += 20
#                 elif dur > 36000:  # >10h
#                     risk_score += 10
#                 elif dur < 60:  # <1min
#                     risk_score += 5
#             except Exception:
#                 pass

#     # 2. Privilege misuse
#     sudo_failures_tuple = metrics.get("sudo_failures", (None, 0, None))
#     sudo_failures = sudo_failures_tuple[1] if isinstance(sudo_failures_tuple, tuple) else 0
#     if sudo_failures > 0:
#         risk_score += min(25, sudo_failures * 10)

#     # 3. Resource anomalies (system metrics already available)
#     if cpu_usage > 90: risk_score += 10
#     if memory_usage > 90: risk_score += 10
#     if disk_usage > 90: risk_score += 10
#     if system_temp > 85: risk_score += 10

#     # 4. Endpoint/device anomalies
#     if len(usb_mounts) > 0:
#         risk_score += len(usb_mounts) * 5

#     if "new_device" in metrics and metrics["new_device"]:
#         risk_score += 15

#     # 5. File/data anomalies
#     if metrics.get("encrypted_files", 0) > 0:
#         risk_score += min(30, metrics["encrypted_files"] * 0.5)

#     if metrics.get("sensitive_file_access", 0) > 0:
#         risk_score += 20

#     # Normalize to 0–100
#     risk_score = min(100, int(risk_score))
#     print(f"Calculated Risk Score: {risk_score}")

    # -------------------
    # Build feature vectors
    # -------------------
    feature_vectors = []
    anomalies = data.get("anomalies")

    if anomalies and isinstance(anomalies, list):
        for anomaly in anomalies:
            event_type = event_type_mapping.get(anomaly.get("Event Type"), 0)
            event_subtype = event_subtype_mapping.get(anomaly.get("Event Sub Type"), 0)
            event_reason = anomaly.get("Event Details", "N/A")

            feature_vectors.append({
                "HEADER": {
                    "sourceId": source_id,
                    "destId": dest_id,
                    "msgId": msg_id
                },
                "MESSAGE": {
                    "eventId": generate_event_id(),
                    "srcId": source_id,
                    "day": date, "month": month, "year": year,
                    "hour": hour, "minute": minute, "second": second,
                    "eventType": event_type,
                    "eventName": event_subtype,
                    "severity": severity_mapping["ALERT"],
                    "eventReason": event_reason,
                    "attackerIp": "unknown",
                    "attackerInfo": "unknown",
                    "username": USERNAME,
                    "perProcessMemory": per_proc_mem,
                    "riskScore": risk_score,
                    "locationData": "INDIA",
                    "pid": os.getpid(),
                    "serviceName": 0,
                    "servicePath": "path/to/service",
                    "deviceType": device_tags_mapping["PC"],
                    "deviceMacId": mac_address,
                    "deviceIp": ip_addresses,
                    "logText": log_text
                }
            })
    else:
        # Fallback: build anomaly from root fields
        feature_vectors.append({
            "HEADER": {
                "sourceId": source_id,
                "destId": dest_id,
                "msgId": msg_id
            },
            "MESSAGE": {
                "eventId": generate_event_id(),
                "srcId": source_id,
                "day": date, "month": month, "year": year,
                "hour": hour, "minute": minute, "second": second,
                "eventType": data.get("event_type", "N/A"),
                "eventName": data.get("event_name", "N/A"),
                "severity": data.get("severity", severity_mapping["ALERT"]),
                "eventReason": data.get("event_reason", "N/A"),
                "attackerIp": "unknown",
                "attackerInfo": "unknown",
                "username": USERNAME,
                "perProcessMemory": per_proc_mem,
                "riskScore": risk_score,
                "locationData": "INDIA",
                "pid": os.getpid(),
                "serviceName": 0,
                "servicePath": "path/to/service",
                "deviceType": device_tags_mapping["PC"],
                "deviceMacId": mac_address,
                "deviceIp": ip_addresses,
                "logText": log_text
            }
        })

    return feature_vectors



# siem_api_url = "http://localhost:8080"
# siem_api_url = "https://httpbin.org/post"
# http://10.229.40.67:5000/api/soc/v0_90/siem/uebaSettingData


def send_json_packet(json_data):
    try:
        # Convert datetimes → ISO strings
        safe_data = json.loads(json.dumps(json_data, default=str))

        #
        # print("[SIEM] Payload →", json.dumps(safe_data, indent=2))

        response = requests.post(
            siem_api_url,
            json=safe_data
        )
        response.raise_for_status()

        logging.info("SENT TO SIEM")
        print(f"[SIEM] SENT successfully → {response.status_code}")
        return True

    except requests.RequestException as e:
        logging.error(f"[SIEM] send failed: {e}")
        print(f"[SIEM] send failed: {e}")
        return False




    