# from SIEM_connector import create_packet
import psycopg2
from datetime import datetime,timedelta
import logging
# from SIEM_connector import send_json_packet
from SIEM_connector import create_packet,send_json_packet

# from rabbit_mq.send import send_to_rabbitmq
import json
import os
import sys
import uuid
import socket
import getpass
import psutil
from psycopg2.extras import Json
from datetime import datetime
import psycopg2, json, logging

# Deduplication cache
ANOMALY_CACHE = {}  # key -> last_seen_timestamp
CACHE_TTL = timedelta(seconds=10)

CONFIG_PATH = os.environ.get("UEBA_CONFIG", "/home/config.json")

try:
    with open(CONFIG_PATH, "r") as f:
        CONFIG = json.load(f)
except Exception as e:
    logging.error(f"[helper] Failed to load CONFIG from {CONFIG_PATH}: {e}")
    CONFIG = {}

DB_CONFIG = {
    'host': CONFIG["local_db"]["host"],
    'user': CONFIG["local_db"]["user"],
    'password': CONFIG["local_db"]["password"],
    'dbname': CONFIG["local_db"]["dbname"]
}


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# sys.path.append("/home/simar/Documents/UEBA_BACKEND")
from structures.structures import * 

    # === New Imports for SIEM packet mapping ===

def generate_event_id():
  return str(uuid.uuid4())
    # return uuid.uuid4().int & ((1 << 63) - 1)

def get_mac_address():
    """Return the system's MAC address."""
    try:
        return ':'.join([
            '{:02x}'.format((uuid.getnode() >> i) & 0xff) 
            for i in range(0, 8 * 6, 8)[::-1]
        ])
    except Exception:
        return "00:00:00:00:00:00"
    
def get_tty_status():
    """Return 'YES' if process has TTY, else 'NO'."""
    try:
        if sys.stdout.isatty() or os.isatty(sys.stdin.fileno()):
            return "YES"
        else:
            return "NO"
    except Exception:
        return "NO"



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



def get_common_system_fields():
    """Return common device + actor fields for anomalies (server side)."""
    try:
        hostname = socket.gethostname()
        username = getpass.getuser()
    except Exception:
        hostname, username = "unknown", "unknown"

    ip_address = get_primary_ip()

    try:
        cpu_times = psutil.Process(os.getpid()).cpu_times()
        cpu_time = cpu_times.user + cpu_times.system
    except Exception:
        cpu_time = 0.0

    # detect tty dynamically
    try:
        tty_status = "YES" if sys.stdout.isatty() else "NO"
    except Exception:
        tty_status = "NO"

    return {
        "device_hostname": hostname,
        "device_username": username,
        "device_ip_add": ip_address,
        "device_mac_id": get_mac_address(),
        "attacker_ip_address": "unknown",   # cannot determine on server side
        "attacker_username": "unknown",     # cannot determine on server side
        "pid": str(os.getpid()),
        "ppid": str(os.getppid()),
        "tty": tty_status,
        "cpu_time": cpu_time
    }

from datetime import datetime

def _to_dt(ts):
    """
    Accepts:
      - dict like {"dd":..,"mm":..,"yyyy":..,"hh":..,"min":..,"ss":..}
      - ISO string
      - datetime
      - None
    Returns datetime (fallback = now()).
    """
    try:
        if isinstance(ts, dict):
            return datetime(
                int(ts.get("yyyy", 1970)),
                int(ts.get("mm", 1)),
                int(ts.get("dd", 1)),
                int(ts.get("hh", 0)),
                int(ts.get("min", 0)),
                int(ts.get("ss", 0)),
            )
        if isinstance(ts, str):
            return datetime.fromisoformat(ts.replace("Z","").replace("z",""))
        if isinstance(ts, datetime):
            return ts
    except Exception:
        pass
    return datetime.now()



def dt_to_struct(dt: datetime) -> STRING_DATE_TIME_FORMAT:
    return STRING_DATE_TIME_FORMAT(
        dd=dt.day, mm=dt.month, yyyy=dt.year,
        hh=dt.hour, min=dt.minute, ss=dt.second
    )


def     build_abnormal_login_logout_packet(raw_anomaly):
    """
    Build SIEM-ready packet for Abnormal Login anomaly.
    Uses map_common_fields() + adds specific fields.
    """
    base = map_common_fields(raw_anomaly)

    # Add anomaly-specific fields
    base.update({
        "abnrml_login_logout": base["timestamp"]  # reuse timestamp here
    })

    # Create dataclass instance
    packet = STRUCT_ABNORMAL_LOGIN_LOGOUT_TIME(
        msg_id=base.get("msg_id"),
        source_id=base.get("source_id"),
        event_id=base.get("event_id"),
        event_type=base.get("event_type"),
        event_name=base.get("event_name"),
        event_reason=base.get("event_reason"),
        timestamp=dt_to_struct(base.get("timestamp")),
        attacker_ip_address=base.get("attacker_ip_address"),
        attacker_username=base.get("attacker_username"),
        device_hostname=base.get("device_hostname"),
        device_username=base.get("device_username"),
        device_mac_id=base.get("device_mac_id"),
        device_ip_add=base.get("device_ip_add"),
        device_type=base.get("device_type"),
        log_text=base.get("log_text"),
        severity=base.get("severity"),
        pid=base.get("pid"),
        ppid=base.get("ppid"),
        tty=base.get("tty"),
        cpu_time=base.get("cpu_time"),
        start_time=dt_to_struct(base.get("start_time")),
        abnrml_login_logout=dt_to_struct(base.get("timestamp"))
    )

    return packet

# def build_anomalous_application_usage_packet(raw_anomaly):
#     """
#     Build SIEM-ready packet for Anomalous Application Usage anomaly.
#     Uses map_common_fields() + adds specific fields.
#     """
#     # Start with the common mapped fields
#     base = map_common_fields(raw_anomaly)

#     # Add anomaly-specific field
#     base.update({
#         "anomalous_application_name": raw_anomaly.get("anomalous_application_name", "unknown")
#     })

#     return base

def build_anomalous_application_usage_packet(raw_anomaly):
    """
    Build SIEM-ready packet for Anomalous Application Usage anomaly.
    Uses map_common_fields() + adds specific fields.
    """
    base = map_common_fields(raw_anomaly)

    # Add anomaly-specific field
    base.update({
        "anomalous_application_name": raw_anomaly.get("anomalous_application_name", "unknown")
    })

    # Create dataclass instance
    packet = STRUCT_ANOMALOUS_APPLICATION_USAGE(
        msg_id=base.get("msg_id"),
        source_id=base.get("source_id"),
        event_id=base.get("event_id"),
        event_type=base.get("event_type"),
        event_name=base.get("event_name"),
        event_reason=base.get("event_reason"),
        timestamp=dt_to_struct(base.get("timestamp")),
        attacker_ip_address=base.get("attacker_ip_address"),
        attacker_username=base.get("attacker_username"),
        device_hostname=base.get("device_hostname"),
        device_username=base.get("device_username"),
        device_mac_id=base.get("device_mac_id"),
        device_ip_add=base.get("device_ip_add"),
        device_type=base.get("device_type"),
        log_text=base.get("log_text"),
        severity=base.get("severity"),
        pid=base.get("pid"),
        ppid=base.get("ppid"),
        tty=base.get("tty"),
        cpu_time=base.get("cpu_time"),
        start_time=dt_to_struct(base.get("start_time")),
        anomalous_application_name=base.get("anomalous_application_name")
    )

    return packet

def build_anomalous_cpu_gpu_ram_consp_packet(raw_anomaly):
    """
    Build SIEM-ready packet for Anomalous CPU/GPU/RAM Consumption anomaly.
    Uses only common mapped fields.
    """
    base = map_common_fields(raw_anomaly)

    # Create dataclass instance
    packet = STRUCT_ANOMALOUS_CPU_GPU_RAM_CONSP(
        msg_id=base.get("msg_id"),
        source_id=base.get("source_id"),
        event_id=base.get("event_id"),
        event_type=base.get("event_type"),
        event_name=base.get("event_name"),
        event_reason=base.get("event_reason"),
        timestamp=dt_to_struct(base.get("timestamp")),
        attacker_ip_address=base.get("attacker_ip_address"),
        attacker_username=base.get("attacker_username"),
        device_hostname=base.get("device_hostname"),
        device_username=base.get("device_username"),
        device_mac_id=base.get("device_mac_id"),
        device_ip_add=base.get("device_ip_add"),
        device_type=base.get("device_type"),
        log_text=base.get("log_text"),
        severity=base.get("severity"),
        pid=base.get("pid"),
        ppid=base.get("ppid"),
        tty=base.get("tty"),
        cpu_time=base.get("cpu_time"),
        start_time=dt_to_struct(base.get("start_time"))
    )

    return packet


def build_anomalous_file_access_packet(raw_anomaly):
    """
    Build SIEM-ready packet for Anomalous File Access anomaly.
    Extends common fields with file-specific details.
    """
    base = map_common_fields(raw_anomaly)

    # Add anomaly-specific fields
    base.update({
        "file_name": raw_anomaly.get("file_name", "N/A"),
        "file_path": raw_anomaly.get("file_path", "N/A")
    })

    # Create dataclass instance
    packet = STRUCT_ANOMALOUS_FILE_ACCESS(
        msg_id=base.get("msg_id"),
        source_id=base.get("source_id"),
        event_id=base.get("event_id"),
        event_type=base.get("event_type"),
        event_name=base.get("event_name"),
        event_reason=base.get("event_reason"),
        timestamp=dt_to_struct(base.get("timestamp")),
        attacker_ip_address=base.get("attacker_ip_address"),
        attacker_username=base.get("attacker_username"),
        device_hostname=base.get("device_hostname"),
        device_username=base.get("device_username"),
        device_mac_id=base.get("device_mac_id"),
        device_ip_add=base.get("device_ip_add"),
        device_type=base.get("device_type"),
        log_text=base.get("log_text"),
        severity=base.get("severity"),
        pid=base.get("pid"),
        ppid=base.get("ppid"),
        tty=base.get("tty"),
        cpu_time=base.get("cpu_time"),
        start_time=dt_to_struct(base.get("start_time")),
        file_name=base.get("file_name"),
        file_path=base.get("file_path")
    )

    return packet


def build_anomalous_user_session_packet(raw_anomaly):
    """
    Build SIEM-ready packet for Anomalous User Session anomaly.
    Uses map_common_fields() + adds specific fields.
    """
    base = map_common_fields(raw_anomaly)

    # Add anomaly-specific field
    base.update({
        "session_duration": float(raw_anomaly.get("session_duration", 0.0))
    })

    # Create dataclass instance
    packet = STRUCT_ANOMALOUS_USER_SESSION(
        msg_id=base.get("msg_id"),
        source_id=base.get("source_id"),
        event_id=base.get("event_id"),
        event_type=base.get("event_type"),
        event_name=base.get("event_name"),
        event_reason=base.get("event_reason"),
        timestamp=dt_to_struct(base.get("timestamp")),
        attacker_ip_address=base.get("attacker_ip_address"),
        attacker_username=base.get("attacker_username"),
        device_hostname=base.get("device_hostname"),
        device_username=base.get("device_username"),
        device_mac_id=base.get("device_mac_id"),
        device_ip_add=base.get("device_ip_add"),
        device_type=base.get("device_type"),
        log_text=base.get("log_text"),
        severity=base.get("severity"),
        pid=base.get("pid"),
        ppid=base.get("ppid"),
        tty=base.get("tty"),
        cpu_time=base.get("cpu_time"),
        start_time=dt_to_struct(base.get("start_time")),
        session_duration=base.get("session_duration")
    )

    return packet


def build_behavioural_change_detection_packet(raw_anomaly):
    """
    Build SIEM-ready packet for Behavioural Change Detection anomaly.
    Uses only the common fields.
    """
    base = map_common_fields(raw_anomaly)

    # Create dataclass instance
    packet = STRUCT_BEHAVIOURAL_CHANGE_DETECTION(
        msg_id=base.get("msg_id"),
        source_id=base.get("source_id"),
        event_id=base.get("event_id"),
        event_type=base.get("event_type"),
        event_name=base.get("event_name"),
        event_reason=base.get("event_reason"),
        timestamp=dt_to_struct(base.get("timestamp")),
        attacker_ip_address=base.get("attacker_ip_address"),
        attacker_username=base.get("attacker_username"),
        device_hostname=base.get("device_hostname"),
        device_username=base.get("device_username"),
        device_mac_id=base.get("device_mac_id"),
        device_ip_add=base.get("device_ip_add"),
        device_type=base.get("device_type"),
        log_text=base.get("log_text"),
        severity=base.get("severity"),
        pid=base.get("pid"),
        ppid=base.get("ppid"),
        tty=base.get("tty"),
        cpu_time=base.get("cpu_time"),
        start_time=dt_to_struct(base.get("start_time"))
    )

    return packet


def build_blk_data_op_moni_detection_packet(raw_anomaly):
    """
    Build SIEM-ready packet for Block Data Operation Monitoring anomaly.
    Extends common fields with block operation details.
    """
    base = map_common_fields(raw_anomaly)

    # Add anomaly-specific fields
    base.update({
        "operation_type": CONFIG["operation_type"].get(raw_anomaly.get("operation_type", "NA"), 0),
        "operation_size": float(raw_anomaly.get("operation_size", 0.0))
    })

    # Create dataclass instance
    packet = STRUCT_BLK_DATA_OP_MONI_DETECTION(
        msg_id=base.get("msg_id"),
        source_id=base.get("source_id"),
        event_id=base.get("event_id"),
        event_type=base.get("event_type"),
        event_name=base.get("event_name"),
        event_reason=base.get("event_reason"),
        timestamp=dt_to_struct(base.get("timestamp")),
        attacker_ip_address=base.get("attacker_ip_address"),
        attacker_username=base.get("attacker_username"),
        device_hostname=base.get("device_hostname"),
        device_username=base.get("device_username"),
        device_mac_id=base.get("device_mac_id"),
        device_ip_add=base.get("device_ip_add"),
        device_type=base.get("device_type"),
        log_text=base.get("log_text"),
        severity=base.get("severity"),
        pid=base.get("pid"),
        ppid=base.get("ppid"),
        tty=base.get("tty"),
        cpu_time=base.get("cpu_time"),
        start_time=dt_to_struct(base.get("start_time")),
        operation_type=base.get("operation_type"),
        operation_size=base.get("operation_size")
    )

    return packet


def build_command_exe_moni_packet(raw_anomaly):
    """
    Build SIEM-ready packet for Command Execution Monitoring anomaly.
    Extends common fields with command-specific details.
    """
    base = map_common_fields(raw_anomaly)

    base.update({
        "command_text": raw_anomaly.get("command_text", "N/A"),
        "command_exe_duration": float(raw_anomaly.get("command_exe_duration", 0.0)),
        "command_repetition": raw_anomaly.get("command_repetition", "NO")  # enforce YES/NO
    })

    # Create dataclass instance
    packet = STRUCT_COMMAND_EXE_MONI(
        msg_id=base.get("msg_id"),
        source_id=base.get("source_id"),
        event_id=base.get("event_id"),
        event_type=base.get("event_type"),
        event_name=base.get("event_name"),
        event_reason=base.get("event_reason"),
        timestamp=dt_to_struct(base.get("timestamp")),
        attacker_ip_address=base.get("attacker_ip_address"),
        attacker_username=base.get("attacker_username"),
        device_hostname=base.get("device_hostname"),
        device_username=base.get("device_username"),
        device_mac_id=base.get("device_mac_id"),
        device_ip_add=base.get("device_ip_add"),
        device_type=base.get("device_type"),
        log_text=base.get("log_text"),
        severity=base.get("severity"),
        pid=base.get("pid"),
        ppid=base.get("ppid"),
        tty=base.get("tty"),
        cpu_time=base.get("cpu_time"),
        start_time=dt_to_struct(base.get("start_time")),
        command_text=base.get("command_text"),
        command_exe_duration=base.get("command_exe_duration"),
        command_repetition=base.get("command_repetition")
    )

    return packet

def build_data_exfiltration_attempts_packet(raw_anomaly):
    """
    Build SIEM-ready packet for Data Exfiltration Attempts anomaly.
    Extends common fields with file transfer + destination details.
    """
    base = map_common_fields(raw_anomaly)

    base.update({
        "port": raw_anomaly.get("port", "N/A"),
        "protocol_used": raw_anomaly.get("protocol_used", "N/A"),
        "file_name": raw_anomaly.get("file_name", "N/A"),
        "file_type": raw_anomaly.get("file_type", "N/A"),
        "transfer_size": float(raw_anomaly.get("transfer_size", 0.0)),
        "destination_ip_add": raw_anomaly.get("destination_ip_add", "N/A"),
        "destination_domain": raw_anomaly.get("destination_domain", "N/A")
    })

    # Create dataclass instance
    packet = STRUCT_DATA_EXFILTRATION_ATTEMPTS_DETECTION(
        msg_id=base.get("msg_id"),
        source_id=base.get("source_id"),
        event_id=base.get("event_id"),
        event_type=base.get("event_type"),
        event_name=base.get("event_name"),
        event_reason=base.get("event_reason"),
        timestamp=dt_to_struct(base.get("timestamp")),
        attacker_ip_address=base.get("attacker_ip_address"),
        attacker_username=base.get("attacker_username"),
        device_hostname=base.get("device_hostname"),
        device_username=base.get("device_username"),
        device_mac_id=base.get("device_mac_id"),
        device_ip_add=base.get("device_ip_add"),
        device_type=base.get("device_type"),
        log_text=base.get("log_text"),
        severity=base.get("severity"),
        port=base.get("port"),
        protocol_used=base.get("protocol_used"),
        file_name=base.get("file_name"),
        file_type=base.get("file_type"),
        transfer_size=base.get("transfer_size"),
        destination_ip_add=base.get("destination_ip_add"),
        destination_domain=base.get("destination_domain")
    )

    return packet



def build_dos_ddos_detection_packet(raw_anomaly):
    """
    Build SIEM-ready packet for DoS/DDoS Detection anomaly.
    Extends common fields with network traffic details.
    """
    base = map_common_fields(raw_anomaly)

    base.update({
        "port": raw_anomaly.get("port", "N/A"),
        "protocol_used": raw_anomaly.get("protocol_used", "N/A"),
        "bytes_sents_or_received": int(raw_anomaly.get("bytes_sents_or_received", 0))
    })

    # Create dataclass instance
    packet = STRUCT_DOS_DDOS_DETECTION(
        msg_id=base.get("msg_id"),
        source_id=base.get("source_id"),
        event_id=base.get("event_id"),
        event_type=base.get("event_type"),
        event_name=base.get("event_name"),
        event_reason=base.get("event_reason"),
        timestamp=dt_to_struct(base.get("timestamp")),
        attacker_ip_address=base.get("attacker_ip_address"),
        attacker_username=base.get("attacker_username"),
        device_hostname=base.get("device_hostname"),
        device_username=base.get("device_username"),
        device_mac_id=base.get("device_mac_id"),
        device_ip_add=base.get("device_ip_add"),
        device_type=base.get("device_type"),
        log_text=base.get("log_text"),
        severity=base.get("severity"),
        port=base.get("port"),
        protocol_used=base.get("protocol_used"),
        bytes_sents_or_received=base.get("bytes_sents_or_received")
    )

    return packet


def build_file_sys_moni_packet(raw_anomaly):
    """
    Build SIEM-ready packet for File System Monitoring anomaly.
    Extends common fields with file operation details.
    """
    base = map_common_fields(raw_anomaly)

    base.update({
        "operation_type": CONFIG["operation_type"].get(raw_anomaly.get("operation_type", "NA"), 0),
        "file_name": raw_anomaly.get("file_name", "N/A"),
        "file_path": raw_anomaly.get("file_path", "N/A"),
        "frequency_count": int(raw_anomaly.get("frequency_count", 0))
    })

    # Create dataclass instance
    packet = STRUCT_FILE_SYS_MONI(
        msg_id=base.get("msg_id"),
        source_id=base.get("source_id"),
        event_id=base.get("event_id"),
        event_type=base.get("event_type"),
        event_name=base.get("event_name"),
        event_reason=base.get("event_reason"),
        timestamp=dt_to_struct(base.get("timestamp")),
        attacker_ip_address=base.get("attacker_ip_address"),
        attacker_username=base.get("attacker_username"),
        device_hostname=base.get("device_hostname"),
        device_username=base.get("device_username"),
        device_mac_id=base.get("device_mac_id"),
        device_ip_add=base.get("device_ip_add"),
        device_type=base.get("device_type"),
        log_text=base.get("log_text"),
        severity=base.get("severity"),
        pid=base.get("pid"),
        ppid=base.get("ppid"),
        tty=base.get("tty"),
        cpu_time=base.get("cpu_time"),
        start_time=dt_to_struct(base.get("start_time")),
        operation_type=base.get("operation_type"),
        file_name=base.get("file_name"),
        file_path=base.get("file_path"),
        frequency_count=base.get("frequency_count")
    )

    return packet



def build_ssh_brute_force_packet(raw_anomaly):
    """
    Build SIEM-ready packet for SSH Brute Force anomaly.
    Extends common fields with brute force–specific details.
    """
    base = map_common_fields(raw_anomaly)

    base.update({
        "port": raw_anomaly.get("port", "22"),  # Default SSH port if not provided
        "protocol_used": raw_anomaly.get("protocol_used", "TCP"),
        "failed_login_attempts": int(raw_anomaly.get("failed_login_attempts", 0)),
        "username_attempted": raw_anomaly.get("username_attempted", "unknown"),
        "login_attempt_rate": int(raw_anomaly.get("login_attempt_rate", 0))
    })

    # Create dataclass instance
    packet = STRUCT_SSH_BRUTE_FORCE_DETECTION(
        msg_id=base.get("msg_id"),
        source_id=base.get("source_id"),
        event_id=base.get("event_id"),
        event_type=base.get("event_type"),
        event_name=base.get("event_name"),
        event_reason=base.get("event_reason"),
        timestamp=dt_to_struct(base.get("timestamp")),
        attacker_ip_address=base.get("attacker_ip_address"),
        attacker_username=base.get("attacker_username"),
        device_hostname=base.get("device_hostname"),
        device_username=base.get("device_username"),
        device_mac_id=base.get("device_mac_id"),
        device_ip_add=base.get("device_ip_add"),
        device_type=base.get("device_type"),
        log_text=base.get("log_text"),
        severity=base.get("severity"),
        port=base.get("port"),
        protocol_used=base.get("protocol_used"),
        failed_login_attempts=base.get("failed_login_attempts"),
        username_attempted=base.get("username_attempted"),
        login_attempt_rate=base.get("login_attempt_rate")
    )

    return packet

def build_unused_acc_activity_packet(raw_anomaly):
    """
    Build SIEM-ready packet for Unused Account Activity anomaly.
    Extends common fields with session and dormant account details.
    """
    base = map_common_fields(raw_anomaly)

    base.update({
        "session_id": raw_anomaly.get("session_id", "N/A"),
        "session_duration": float(raw_anomaly.get("session_duration", 0.0)),
        "dormant_duration": float(raw_anomaly.get("dormant_duration", 0.0))
    })

    # Create dataclass instance
    packet = STRUCT_UNUSED_ACC_ACTIVITY(
        msg_id=base.get("msg_id"),
        source_id=base.get("source_id"),
        event_id=base.get("event_id"),
        event_type=base.get("event_type"),
        event_name=base.get("event_name"),
        event_reason=base.get("event_reason"),
        timestamp=dt_to_struct(base.get("timestamp")),
        attacker_ip_address=base.get("attacker_ip_address"),
        attacker_username=base.get("attacker_username"),
        device_hostname=base.get("device_hostname"),
        device_username=base.get("device_username"),
        device_mac_id=base.get("device_mac_id"),
        device_ip_add=base.get("device_ip_add"),
        device_type=base.get("device_type"),
        log_text=base.get("log_text"),
        severity=base.get("severity"),
        pid=base.get("pid"),
        ppid=base.get("ppid"),
        tty=base.get("tty"),
        cpu_time=base.get("cpu_time"),
        start_time=dt_to_struct(base.get("start_time")),
        session_id=base.get("session_id"),
        session_duration=base.get("session_duration"),
        dormant_duration=base.get("dormant_duration")
    )

    return packet


def build_privileged_user_moni_packet(raw_anomaly):
    """
    Build SIEM-ready packet for Privileged User Monitoring anomaly.
    Extends common fields with user role information.
    """
    base = map_common_fields(raw_anomaly)

    base.update({
        "user_role": raw_anomaly.get("user_role", "standard")  # default to standard if not privileged
    })

    # Create dataclass instance
    packet = STRUCT_PRIVILEGED_USER_MONI(
        msg_id=base.get("msg_id"),
        source_id=base.get("source_id"),
        event_id=base.get("event_id"),
        event_type=base.get("event_type"),
        event_name=base.get("event_name"),
        event_reason=base.get("event_reason"),
        timestamp=dt_to_struct(base.get("timestamp")),
        attacker_ip_address=base.get("attacker_ip_address"),
        attacker_username=base.get("attacker_username"),
        device_hostname=base.get("device_hostname"),
        device_username=base.get("device_username"),
        device_mac_id=base.get("device_mac_id"),
        device_ip_add=base.get("device_ip_add"),
        device_type=base.get("device_type"),
        log_text=base.get("log_text"),
        severity=base.get("severity"),
        pid=base.get("pid"),
        ppid=base.get("ppid"),
        tty=base.get("tty"),
        cpu_time=base.get("cpu_time"),
        start_time=dt_to_struct(base.get("start_time")),
        user_role=base.get("user_role")
    )

    return packet

def build_privilege_escalation_moni_packet(raw_anomaly):
    """
    Build SIEM-ready packet for Privilege Escalation Monitoring anomaly.
    Extends common fields with escalation-specific details.
    """
    base = map_common_fields(raw_anomaly)

    # Add privilege escalation–specific fields
    base.update({
        "privilege_escalation_attempt": raw_anomaly.get("privilege_escalation_attempt", "NO"),  # enforce YES/NO
        "privilege_escalation_cmd": raw_anomaly.get("privilege_escalation_cmd", "N/A"),
        "source_role": raw_anomaly.get("source_role", "unknown"),
        "target_role": raw_anomaly.get("target_role", "unknown")
    })

    # Create dataclass instance
    packet = STRUCT_PRIVILEGE_ESCALATION_MONI(
        msg_id=base.get("msg_id"),
        source_id=base.get("source_id"),
        event_id=base.get("event_id"),
        event_type=base.get("event_type"),
        event_name=base.get("event_name"),
        event_reason=base.get("event_reason"),
        timestamp=dt_to_struct(base.get("timestamp")),
        attacker_ip_address=base.get("attacker_ip_address"),
        attacker_username=base.get("attacker_username"),
        device_hostname=base.get("device_hostname"),
        device_username=base.get("device_username"),
        device_mac_id=base.get("device_mac_id"),
        device_ip_add=base.get("device_ip_add"),
        device_type=base.get("device_type"),
        log_text=base.get("log_text"),
        severity=base.get("severity"),
        pid=base.get("pid"),
        ppid=base.get("ppid"),
        tty=base.get("tty"),
        cpu_time=base.get("cpu_time"),
        start_time=dt_to_struct(base.get("start_time")),
        privilege_escalation_attempt=base.get("privilege_escalation_attempt"),
        privilege_escalation_cmd=base.get("privilege_escalation_cmd"),
        source_role=base.get("source_role"),
        target_role=base.get("target_role")
    )

    return packet


def map_common_fields(raw_anomaly):

    from datetime import datetime

    ts_str = raw_anomaly.get("timestamp", datetime.now().isoformat())
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z","").replace("z",""))
    except Exception:
        dt = datetime.now()
    # print("333333333333333333333333333")

    event_type = CONFIG["event_type"].get(raw_anomaly.get("event_type", "NA"), 0)
    event_name = CONFIG["event_name"].get(raw_anomaly.get("event_name", "NA"), 0)
    msg_id = CONFIG["msg_id"].get(raw_anomaly.get("msg_id", "NA"), 0)
    # print("event_type:", event_type)
    # print("event_name:", event_name)
    # print("msg_id:", msg_id)

    base = {
        "msg_id": msg_id,
        # "source_id": CONFIG.get("source_id", 0),
        # "dest_id": CONFIG.get("dest_id", 0),
        "source_id": str(CONFIG.get("source_id", "")),
        "dest_id": str(CONFIG.get("dest_id", "")),
        "event_id": generate_event_id(),                    # uuid string
        "event_type": event_type,
        "event_name": event_name,
        "event_reason": raw_anomaly.get("event_reason", "N/A"),
        "timestamp": dt,                                    # <-- datetime (DB TIMESTAMP)
        "device_type": CONFIG["device_type"].get(raw_anomaly.get("device_type", "PC"), 2),
        "log_text": raw_anomaly.get("log_text", json.dumps(raw_anomaly)),
        "severity": CONFIG["mappings"]["severity"].get(raw_anomaly.get("severity", "ALERT"), 11),
        "start_time": dt                                    # <-- datetime (DB TIMESTAMP)
    }

    base.update(get_common_system_fields())
    return base




def is_duplicate_anomaly(message):
    """Check if this anomaly is a duplicate based on key fields."""
    key = (
        message.get("eventType"),
        message.get("eventName"),
        message.get("username"),
        message.get("deviceMacId"),
        str(message.get("logText"))
    )
    now = datetime.now()

    # Expire old entries
    if key in ANOMALY_CACHE:
        if now - ANOMALY_CACHE[key] < CACHE_TTL:
            return True  # duplicate
    ANOMALY_CACHE[key] = now
    return False


def ensure_raw_analysis_log_exists():
    connection = psycopg2.connect(**DB_CONFIG)
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS raw_analysis_log (
            id SERIAL PRIMARY KEY,
            event_id VARCHAR(255),
            user_id VARCHAR(255),
            timestamp TIMESTAMP,
            event_type VARCHAR(255),
            event_subtype VARCHAR(255),
            analysis_reason TEXT,
            risk_score FLOAT,
            review_status VARCHAR(50) DEFAULT 'pending',
            reviewer_comments TEXT
        );
    """)
    connection.commit()
    cursor.close()
    connection.close()

def store_raw_analysis(event, analysis_reason, risk_score):
    connection = psycopg2.connect(**DB_CONFIG)
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO raw_analysis_log (
            event_id, user_id, timestamp, event_type, event_subtype, analysis_reason, risk_score
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (
        event.get("event_id", "N/A"),
        event.get("username", "N/A"),
        event.get("timestamp", datetime.now()),
        event.get("event_type", "N/A"),
        event.get("event_subtype", "N/A"),
        analysis_reason,
        risk_score
    ))
    connection.commit()
    cursor.close()
    connection.close()
    print("Stored authentication event to Authentication Table.")


def store_anomaly_to_database_and_siem(alert_json):
    """Store anomaly into PostgreSQL and send it to SIEM."""
    try:
        # 1) Build feature vectors from input
        feature_vectors = create_packet(alert_json)

        # 2) DB connect
        connection = psycopg2.connect(**DB_CONFIG)
        cursor = connection.cursor()

        # 3) Ensure table (types shown as VARCHAR to match historical data; no-op if table already exists)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS anomalies_log (
                id SERIAL PRIMARY KEY,
                event_id VARCHAR(255),
                user_id VARCHAR(255),
                timestamp TIMESTAMP,
                event_type VARCHAR(32),
                event_subtype VARCHAR(32),
                severity VARCHAR(32),
                attacker_info TEXT,
                component VARCHAR(255),
                resource TEXT,
                event_reason TEXT,
                device_ip VARCHAR(50),
                device_mac VARCHAR(50),
                log_text TEXT,
                risk_score FLOAT
            );
        """)
        connection.commit()

        # 4) Insert query
        insert_query = """
        INSERT INTO anomalies_log (
            event_id, user_id, timestamp, event_type, event_subtype, severity,
            attacker_info, component, resource, event_reason,
            device_ip, device_mac, log_text, risk_score
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        for i, feature_vector in enumerate(feature_vectors):
            message = feature_vector.get("MESSAGE", {})

            # Required fields with defaults
            required_fields = [
                "eventId", "username", "eventType", "eventName",
                "severity", "attackerInfo", "eventReason",
                "deviceIp", "deviceMacId", "logText"
            ]
            for field in required_fields:
                message.setdefault(field, "N/A")

            try:
                # --- Map codes via CONFIG, then force strings for DB/SIEM ---
                event_type_code = CONFIG["event_type"].get(str(message["eventType"]), message["eventType"])
                event_subtype_code = CONFIG["event_name"].get(str(message["eventName"]), message["eventName"])
                severity_code = CONFIG["mappings"]["severity"].get(str(message["severity"]), message["severity"])

                event_type_str = str(event_type_code)
                event_subtype_str = str(event_subtype_code)
                severity_str = str(severity_code)

                # Deduplication (compare as TEXT)
                cursor.execute("""
                    SELECT COUNT(*) FROM anomalies_log
                    WHERE event_type::text = %s
                      AND event_subtype::text = %s
                      AND log_text = %s
                      AND device_mac = %s
                      AND timestamp > NOW() - INTERVAL '10 seconds'
                """, (
                    event_type_str,
                    event_subtype_str,
                    message["logText"],
                    message["deviceMacId"]
                ))
                if cursor.fetchone()[0] > 0:
                    continue  # duplicate → skip

                # Insert
                cursor.execute(insert_query, (
                    message["eventId"],
                    message["username"],
                    datetime.now(),
                    event_type_str,
                    event_subtype_str,
                    severity_str,
                    message["attackerInfo"],
                    message.get("component", "N/A"),
                    message.get("resource_info", "N/A"),
                    message["eventReason"],
                    message["deviceIp"],
                    message["deviceMacId"],
                    message["logText"],
                    float(message.get("riskScore", 0.0))
                ))
                connection.commit()
                print(f"Successfully inserted in anomalies_log table {i+1}")

                # --- Build SIEM payload (select single ids, not whole maps) ---
                now = datetime.now()

                # msgId from mapping
                msg_map = CONFIG.get("msg_id", {})
                msg_key = alert_json.get("msg_id") or message.get("msg_id") or "UEBA_SIEM_ANOMALOUS_USER_SESSION_MSG"
                msg_id_str = str(msg_map.get(msg_key, 5))

                # deviceType from mapping (default PC)
                dev_map = CONFIG.get("device_type", {})
                dev_code = message.get("deviceType")
                if dev_code is None:
                    dev_code = dev_map.get("PC", 2)
                device_type_str = str(dev_code)

                siem_msg = {
                    "MESSAGE": {
                        "eventId": message["eventId"],
                        "msgId": msg_id_str,
                        "srcId": str(CONFIG.get("source_id", "2")),
                        "year": now.year,
                        "month": now.month,
                        "day": now.day,
                        "hour": now.hour,
                        "minute": now.minute,
                        "second": now.second,
                        "eventType": event_type_str,
                        "eventName": event_subtype_str,
                        "severity": severity_str,
                        "eventReason": message["eventReason"],
                        "attackerIp": message.get("attackerIp", "N/A"),
                        "attackerInfo": message["attackerInfo"],
                        "deviceHostname": socket.gethostname(),
                        "deviceUsername": message.get("username", "unknown"),
                        "serviceName": message.get("component", "N/A"),
                        "servicePath": message.get("resource_info", "N/A"),
                        "deviceType": device_type_str,
                        "destinationIp": message.get("destinationIp", "N/A"),
                        "deviceMacId": message["deviceMacId"],
                        "deviceIp": message["deviceIp"],
                        "logText": message["logText"],
                        "url": None
                    }
                }

                print(">>> Sending SIEM payload:\n", json.dumps(siem_msg, indent=2), flush=True)
                send_json_packet(siem_msg)

            except Exception as e:
                print(f"Error inserting record: {e}")
                print(f"Problematic message: {message}")
                connection.rollback()

    except Exception as e:
        logging.error(f"Error during database/siem operation: {str(e)}")

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def store_siem_ready_packet(siem_packet):
    # print("[DEBUG] Final SIEM packet:", json.dumps(siem_packet, indent=2, default=str))

    """
    Store the SIEM-ready anomaly packet into a unified table
    (only common fields, extra_fields dropped for now) and forward to SIEM.
    """
    try:
        connection = psycopg2.connect(**DB_CONFIG)
        cursor = connection.cursor()

        # 1. Ensure table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS siem_anomalies_log (
                id SERIAL PRIMARY KEY,
                msg_id INT,
                source_id TEXT,
                event_id VARCHAR(255),
                event_type INT,
                event_name TEXT,
                event_reason TEXT,
                timestamp TIMESTAMP,
                attacker_ip_address TEXT,
                attacker_username TEXT,
                device_hostname TEXT,
                device_username TEXT,
                device_mac_id TEXT,
                device_ip_add TEXT,
                device_type INT,
                log_text TEXT,
                severity INT,
                pid TEXT,
                ppid TEXT,
                tty TEXT,
                cpu_time FLOAT,
                start_time TIMESTAMP,
                extra_fields JSONB
            );
        """)
        connection.commit()

        # 2. Normalize values for DB types
        severity_db   = siem_packet.get("severity") or siem_packet.get("sverity") or 0
        timestamp_db  = _to_dt(siem_packet.get("timestamp"))     # handles dict/str/datetime/None
        start_time_db = _to_dt(siem_packet.get("start_time"))    # handles dict/str/datetime/None

        # 3. Insert record
        cursor.execute("""
            INSERT INTO siem_anomalies_log (
                msg_id, source_id, event_id, event_type, event_name, event_reason,
                timestamp, attacker_ip_address, attacker_username,
                device_hostname, device_username, device_mac_id, device_ip_add,
                device_type, log_text, severity, pid, ppid, tty, cpu_time,
                start_time
            ) VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s,
                %s
            )
        """, (
            siem_packet.get("msg_id"),
            siem_packet.get("source_id"),
            str(siem_packet.get("event_id")),     # DB column is VARCHAR
            siem_packet.get("event_type"),
            siem_packet.get("event_name"),        # TEXT column; int OK, PG will cast, but fine as-is
            siem_packet.get("event_reason"),
            timestamp_db,
            siem_packet.get("attacker_ip_address"),
            siem_packet.get("attacker_username"),
            siem_packet.get("device_hostname"),
            siem_packet.get("device_username"),
            siem_packet.get("device_mac_id"),
            siem_packet.get("device_ip_add"),
            siem_packet.get("device_type"),
            siem_packet.get("log_text"),
            severity_db,
            siem_packet.get("pid"),
            siem_packet.get("ppid"),
            siem_packet.get("tty"),
            siem_packet.get("cpu_time"),
            start_time_db
        ))

        connection.commit()

        # 4. Forward packet to SIEM (send original dict with structured timestamps)
             # To be done after phase 1 DO NOT REMOVE FROM HERE.
        # success = send_json_packet(siem_packet)

        # if success:
        #     logging.info(f"[SIEM] SENT anomaly: {siem_packet}")
        # else:
        #     logging.warning("[SIEM] Send failed for anomaly")

    except Exception as e:
        logging.error(f"[helper] Error storing/sending SIEM packet: {e}")
        if 'connection' in locals():
            connection.rollback()
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()
