import os
import json
import re
import uuid
import time
import logging
import psutil
# from kafka import KafkaProducer
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import ipaddress
from queue import Queue
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from datetime import datetime


from kafka_producer.new_log_monitor import (
    get_gpu_usage, get_open_files, get_total_files, get_response_time,
    get_system_temperature, get_encrypted_files, collect_usb_info,
    get_num_open_windows, get_num_gui_processes, get_failed_logins,
    get_recent_remote_logins, get_external_devices, get_recent_sudo_failures,
    check_recent_unlock, get_failed_ssh_attempts, get_lan_and_internet_ips,
    count_cron_jobs, get_avg_load, get_installed_software_count,
    get_last_unlock, get_disk_io_rate, get_new_user_creations,
    get_failed_logins_by_user,get_failed_logins_by_ip,get_expired_credential_attempts,
    get_dictionary_attack_signatures,get_per_process_memory_usage,get_command_executions,get_cpu_usage,get_successful_logins,
    get_account_lockouts,detect_reverse_shell_events,
    track_application_usage,track_process_executions,get_failed_password_changes,get_io_wait_time,get_context_switches,get_startup_latency
    # ,detect_privilege_escalation
)
# from new_log_monitor import *

from kafka_producer.new_log_monitor import  _follow_unlocks
from threading import Thread

# Start unlock monitoring thread
Thread(target=_follow_unlocks, daemon=True).start()

app_usage_queue = Queue()

def run_app_tracker():
    for record in track_application_usage():
        app_usage_queue.put(record)

Thread(target=run_app_tracker, daemon=True).start()

process_event_queue = Queue()

def run_process_tracker():
    for event in track_process_executions(poll_interval=2):
        process_event_queue.put(event)

Thread(target=run_process_tracker, daemon=True).start()

def convert_datetime(obj):
    if isinstance(obj, dict):
        return {k: convert_datetime(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_datetime(i) for i in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    else:
        return obj


# ─── Deduplication Cache ─────────────────────────────────────────────────────
sent_event_cache = {
    "new_users": set(),
    "account_lockouts": 0,
}

last_sent_payload = None

def strip_volatile_fields(d):
    # Remove fields like timestamp and login_time before comparing
    volatile_keys = {"timestamp", "login_time"}
    return {k: v for k, v in d.items() if k not in volatile_keys}


# ─── Load central kafka_config.json ──────────────────────────────────────────
CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH) as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
UDP_PORT = config["udp"]["server_port"]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


USERNAME = psutil.users()[0].name if psutil.users() else "Unknown"



# ─── Metric collection ───────────────────────────────────────────────────────
def collect_metrics():
    # cfg = _load_config()

    # Precompute static values
    now_str   = time.strftime('%Y-%m-%d %H:%M:%S')
    net_io    = psutil.net_io_counters()
    pid_count = len(psutil.pids())


    # Prepare device filter based on config
    # excl_patterns = [re.compile(p) for p in cfg.get("device_exclude_patterns", [])]
    # def _filtered_devices():
    #     raw = get_external_devices()
    #     return [d for d in raw if not any(rx.search(d.get("name","")) for rx in excl_patterns)]

    pw_fail_ts, pw_fail_count, pw_fail_users = get_failed_password_changes()

    # Build all dynamic collectors
    collectors = {
        "cpu_usage":           get_cpu_usage,#psutil.cpu_percent,
        "memory_usage":        lambda: psutil.virtual_memory().percent,
        "startup_latency":      get_startup_latency,
        "per_process_memory":        lambda: get_per_process_memory_usage(),
        "active_processes":    lambda: pid_count,
        "failed_logins":       get_failed_logins,
        "failed_logins_by_user":             get_failed_logins_by_user,
        "failed_logins_by_ip":               get_failed_logins_by_ip,
        "expired_credential_attempts":       get_expired_credential_attempts,
        "dictionary_attack_signatures":      get_dictionary_attack_signatures,
        # "total_files":         get_total_files,
        "total_threads":       lambda: sum(p.num_threads() for p in psutil.process_iter(attrs=['num_threads'])),
        "open_files":          get_open_files,
        "num_gui_processes":   get_num_gui_processes,
        "num_open_windows":    get_num_open_windows,
        "gpu_usage":           get_gpu_usage,
        "system_temperature":  get_system_temperature,
        "io_wait_time":        get_io_wait_time,
        "context_switches":    get_context_switches,
        "response_time":       get_response_time,
        "username":            lambda: USERNAME,
        "failed_ssh_attempts": get_failed_ssh_attempts,
        # "sensitive_dirs":      lambda: cfg.get("sensitive_dirs", []),
        "remote_ip":           get_recent_remote_logins,
        "num_cron_jobs":       count_cron_jobs,
        "total_processes":     lambda: pid_count,
        "avg_load":            get_avg_load,
        "software_installed":  get_installed_software_count,
        # "devices":             _filtered_devices,
        "encrypted_files":     get_encrypted_files,
        "usbs":                collect_usb_info,
        "mac_address":         lambda: ':'.join(
                                    '{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                                    for ele in range(40, -1, -8)
                                ) if uuid.getnode() else "Unknown",
        "ip_addresses":         get_lan_and_internet_ips,
        "sudo_command_failures":  get_recent_sudo_failures,
        # "account_lockouts": get_account_lockouts,
        "locked_users": lambda: get_account_lockouts(),
        # "failed_password_changes": lambda: get_failed_password_changes()[1],
        # "users_failed_password_change": lambda: get_failed_password_changes()[2],
        "failed_password_changes": lambda: pw_fail_count,
        "users_failed_password_change":  lambda: pw_fail_users,
        #  "new_users": get_new_user_creations()
        "new_users": lambda: get_new_user_creations(),
        "successful_logins": lambda: get_successful_logins(),
	    # "privilege_escalation_attempts": detect_privilege_escalation,
        "reverse_shell_events": detect_reverse_shell_events,
        "application_usage": lambda: list(app_usage_queue.queue),
        "process_events":   lambda: list(process_event_queue.queue)

    }

    # Run in parallel, timeout after 4s, fill any missing with None
    results = {}
    with ThreadPoolExecutor(max_workers=len(collectors)) as exe:
        future_to_key = {exe.submit(fn): key for key, fn in collectors.items()}
        try:
            for fut in as_completed(future_to_key, timeout=6):
                key = future_to_key[fut]
                try:
                    results[key] = fut.result()
                except Exception as e:
                    logging.error(f"collect_metrics: error in {key}: {e}")
                    results[key] = None
        except Exception:
            logging.warning("collect_metrics: timeout, missing some metrics")
        # backfill any that didn't complete
        for key in collectors:
            results.setdefault(key, None)
    try:
        results["login_time"] = check_recent_unlock(tail_lines=1000, window_secs=10)
    except Exception as e:
        logging.error(f"collect_metrics: check_recent_unlock failed: {e}")
        results["login_time"] = None

    try:
        results["command_executions"] = get_command_executions()
    except Exception as e:
        logging.error(f"collect_metrics: get_command_executions failed: {e}")
        results["command_executions"] = []   

    read_rate, write_rate = get_disk_io_rate()
    results["disk_read_rate"]  = read_rate
    results["disk_write_rate"] = write_rate

    # Assemble final payload in the exact same order
    #         "account_lockouts": results["account_lockouts"],
    #    "new_users": results["new_users"]  added by simar

    metrics = {
        "timestamp":             now_str,
        "cpu_usage":             results["cpu_usage"],
        "memory_usage":          results["memory_usage"],
        "startup_latency":       results["startup_latency"],
        "per_process_memory":    results["per_process_memory"],
        "disk_read_rate":        results["disk_read_rate"],
        "disk_write_rate":       results["disk_write_rate"],
        "network_bytes_sent":    net_io.bytes_sent,
        "network_bytes_recv":    net_io.bytes_recv,
        "network_packets_sent":  net_io.packets_sent,
        "network_packets_recv":  net_io.packets_recv,
        "active_processes":      results["active_processes"],
        "failed_logins":         results["failed_logins"],
        "failed_logins_by_user":         results["failed_logins_by_user"],
        "failed_logins_by_ip":           results["failed_logins_by_ip"],
        "expired_credential_attempts":   results["expired_credential_attempts"],
        "dictionary_attack_signatures":  results["dictionary_attack_signatures"],
        # "total_files":           results["total_files"],
        "total_threads":         results["total_threads"],
        "open_files":            results["open_files"],
        "num_gui_processes":     results["num_gui_processes"],
        "num_open_windows":      results["num_open_windows"],
        "gpu_usage":             results["gpu_usage"],
        "system_temperature":    results["system_temperature"],
        "io_wait_time":          results["io_wait_time"],
        "context_switches":      results["context_switches"],
        "response_time":         results["response_time"],
        "username":              results["username"],
        "failed_ssh_attempts":   results["failed_ssh_attempts"],
        # "sensitive_dirs":        results["sensitive_dirs"],
        "remote_ip":             results["remote_ip"],
        "num_cron_jobs":         results["num_cron_jobs"],
        "total_processes":       results["total_processes"],
        "avg_load":              results["avg_load"],
        "software_installed":    results["software_installed"],
        # "devices":               results["devices"],
        "encrypted_files":       results["encrypted_files"],
        "sudo_failures":         results["sudo_command_failures"],
        # "privilege_escalation_attempts": results["privilege_escalation_attempts"],
        "reverse_shell_events": results["reverse_shell_events"],
        "mac_address":           results["mac_address"],
        "ip_addresses":          results["ip_addresses"],
        # "account_lockouts":      results["account_lockouts"],
        "locked_users":          results["locked_users"],
        "account_lockouts":      len(results["locked_users"]),
        "new_users":             results["new_users"],
        "failed_password_changes": results["failed_password_changes"],
        "users_failed_password_change": results["users_failed_password_change"],
        "command_executions":    results["command_executions"],
        "successful_logins":     results["successful_logins"],
        "application_usage":     results["application_usage"],
        "process_events":        results["process_events"],        
    }
    
    # Convert datetime fields in application usage records to ISO strings
    if results.get("application_usage"):
        for record in results["application_usage"]:
            for key in ("start_time", "end_time", "timestamp"):
                if key in record and isinstance(record[key], datetime):
                    record[key] = record[key].isoformat()

    # Convert datetime fields in process events to ISO strings
    if results.get("process_events"):
        for record in results["process_events"]:
            for key in ("start_time", "end_time", "timestamp"):
                if key in record and isinstance(record[key], datetime):
                    record[key] = record[key].isoformat()

    # Clear app usage queue
    while not app_usage_queue.empty():
        app_usage_queue.get()
    
    while not process_event_queue.empty():
        process_event_queue.get()

    metrics["hostname"] = socket.gethostname()

    return metrics




# # ─── Entry point ─────────────────────────────────────────────────────────────
# if __name__ == "__main__":
#     while True:

#         data = collect_metrics()
#         data["login_time"] = get_last_unlock()
#         data = convert_datetime(data) 
        
#         if data:
#             try:
#                 producer.send('system-metrics', data)
#                 #logging.info(f"Sent metrics: {data}")
                
#                 important_metrics = {
#                 "timestamp": data.get("timestamp"),
#                 "cpu_usage": data.get("cpu_usage"),
#                 "memory_usage": data.get("memory_usage"),
#                 "startup_latency": data.get("startup_latency"),
#                 # "per_process_memory": data.get("per_process_memory"),
#                 "disk_read_rate": data.get("disk_read_rate"),
#                  "disk_write_rate": data.get("disk_write_rate"),
#                 "network_bytes_sent": data.get("network_bytes_sent"),
#                  "network_bytes_recv": data.get("network_bytes_recv"),
#                 "username": data.get("username"),
#                 # "failed_logins": data.get("failed_logins"),
#                 # "failed_logins_by_user": data.get("failed_logins_by_user"),
#                 # "failed_logins_by_ip": data.get("failed_logins_by_ip"),
#                 # "failed_ssh_attempts": data.get("failed_ssh_attempts"),
#                 # "expired_credential_attempts": data.get("expired_credential_attempts"),
#                 # "dictionary_attack_signatures": data.get("dictionary_attack_signatures"),
#                 # "gpu_usage": data.get("gpu_usage"),
#                 "system_temperature": data.get("system_temperature"),
#                 "avg_load": data.get("avg_load"),
#                 # "account_lockouts": data.get("account_lockouts"),
#                 # "locked_users": data.get("locked_users"),
#                 # "new_users": data.get("new_users"),        
#                 # "mac_address": data.get("mac_address"),
#                 # "ip_addresses": data.get("ip_addresses"),
#                 #   "successful_logins": data.get("successful_logins"),
# 		          # "sudo_failures":         data.get("sudo_failures"), 
#                 # "privilege_escalation_attempts": data.get("privilege_escalation_attempts"),
#                 # "reverse_shell_events": data.get("reverse_shell_events"),
#                 # "application_usage": data.get("application_usage"),
#                 # "process_events": data.get("process_events"),
#                 # "failed_password_changes": data.get("failed_password_changes"),
#                 # "users_failed_password_change": data.get("users_failed_password_change"),
#                 # "command_executions": data.get("command_executions"),
#                 # "hostname": data.get("hostname"),
#                 "response_time": data.get("response_time"),
#                 "io_wait_time": data.get("io_wait_time"),
#                  "context_switches": data.get("context_switches"),
#                 }

#                 # logging.info(f"Sent metrics: {data}")
#                 # print("\033[96m[Producer] Sent metrics:\n" + json.dumps(data, indent=4) + "\033[0m") 
#                 print("Key Metrics:\n" + json.dumps(important_metrics, indent=4) + "\033[0m")
   
#             except Exception as e:
#                 logging.error(f"Kafka send error: {e}")
#         time.sleep(5)
def main():
    while True:
        data = collect_metrics()
        data["login_time"] = get_last_unlock()
        data = convert_datetime(data)
        print("\033[1;32m  !!!!!System Monitor Producer started!!!!!!\033[0m") 
        
        if data:
            try:
                # producer.send('system-metrics', data)
                data["topic"] = "system-metrics"
                sock.sendto(json.dumps(data).encode("utf-8"), (UDP_IP, UDP_PORT))
                print(f"[Producer] Sent {len(json.dumps(data))} bytes to {UDP_IP}:{UDP_PORT}")

                
                important_metrics = {
                    "timestamp": data.get("timestamp"),
                    "cpu_usage": data.get("cpu_usage"),
                    "memory_usage": data.get("memory_usage"),
                    "startup_latency": data.get("startup_latency"),
                    "disk_read_rate": data.get("disk_read_rate"),
                    "disk_write_rate": data.get("disk_write_rate"),
                    "network_bytes_sent": data.get("network_bytes_sent"),
                    "network_bytes_recv": data.get("network_bytes_recv"),
                    "username": data.get("username"),
                    "system_temperature": data.get("system_temperature"),
                    "avg_load": data.get("avg_load"),
                    "response_time": data.get("response_time"),
                    "io_wait_time": data.get("io_wait_time"),
                    "context_switches": data.get("context_switches"),
                    "command_executions": data.get("command_executions"),
                    "new_users": data.get("new_users"),
                    "successful_logins": data.get("successful_logins"),
                    "failed_logins": data.get("failed_logins"),
                    "failed_logins_by_user": data.get("failed_logins_by_user"),
                    "failed_logins_by_ip": data.get("failed_logins_by_ip"),
                    "failed_ssh_attempts": data.get("failed_ssh_attempts"),
                    "failed_password_changes": data.get("failed_password_changes"),
                    "account_lockouts": data.get("account_lockouts"),
                    "locked_users": data.get("locked_users"),
                
                }
                print("Key Metrics:\n" + json.dumps(important_metrics, indent=4) + "\033[0m")
   
            except Exception as e:
                logging.error(f"Kafka send error: {e}")
        time.sleep(5)


if __name__ == "__main__":
    main()

