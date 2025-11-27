import os
import json
import re
import uuid
import time
import logging
import psutil
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
    get_last_unlock, get_disk_io_rate, get_new_user_creations,get_user_deletions,get_user_modifications,
    get_failed_logins_by_user,get_failed_logins_by_ip,get_expired_credential_attempts,
    get_dictionary_attack_signatures,get_per_process_memory_usage,get_command_executions,get_cpu_usage,get_successful_logins,
    get_account_lockouts,detect_reverse_shell_events,
    track_application_usage,get_failed_password_changes,get_io_wait_time,get_context_switches,get_startup_latency,
    collect_network_status,init_failed_login_reader,get_kernel_latency, get_scheduling_latency,
    get_realtime_latency
    # ,track_process_executions
    # ,detect_privilege_escalation
)

from kafka_producer.new_log_monitor import  _follow_unlocks
from threading import Thread    


# ─── Load central kafka_config.json ──────────────────────────────────────────
CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH) as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
UDP_PORT = config["udp"]["server_port"]
SCAN_INTERVAL = int(config.get("SCAN_INTERVAL", 5))

init_failed_login_reader()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


# Start unlock monitoring thread
Thread(target=_follow_unlocks, daemon=True).start()

app_usage_queue = Queue()

def run_app_tracker():
    for record in track_application_usage():
        app_usage_queue.put(record)

Thread(target=run_app_tracker, daemon=True).start()


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
sent_event_cache["locked_users"] = set()

last_sent_payload = None

def strip_volatile_fields(d):
    # Remove fields like timestamp and login_time before comparing
    volatile_keys = {"timestamp", "login_time"}
    return {k: v for k, v in d.items() if k not in volatile_keys}


USERNAME = psutil.users()[0].name if psutil.users() else "Unknown"

def collect_metrics():

    # Precompute static values
    now_str   = time.strftime('%Y-%m-%d %H:%M:%S')
    net_io    = psutil.net_io_counters()
    pid_count = len(psutil.pids())

    pw_fail_ts, pw_fail_count, pw_fail_users = get_failed_password_changes()

    # Build all dynamic collectors
    collectors = {
        "cpu_usage":                get_cpu_usage,
        "memory_usage":             lambda: psutil.virtual_memory().percent,
        "ram_usage":                lambda: psutil.virtual_memory().used / (1024 * 1024),
        "startup_latency":          get_startup_latency,
        

        "per_process_memory":       get_per_process_memory_usage,
        "active_processes":         lambda: pid_count,
        "failed_logins":            get_failed_logins,
        "failed_logins_by_user":    get_failed_logins_by_user,
        "failed_logins_by_ip":      get_failed_logins_by_ip,
        "expired_credential_attempts": get_expired_credential_attempts,
        "dictionary_attack_signatures": get_dictionary_attack_signatures,
        "total_threads":            lambda: sum(p.num_threads() for p in psutil.process_iter(attrs=['num_threads'])),
        "open_files":               get_open_files,
        "num_gui_processes":        get_num_gui_processes,
        "num_open_windows":         get_num_open_windows,
        "gpu_usage":                get_gpu_usage,
        "system_temperature":       get_system_temperature,
        "io_wait_time":             get_io_wait_time,
        "context_switches":         get_context_switches,
        "response_time":            get_response_time,
        "username":                 lambda: USERNAME,
        "failed_ssh_attempts":      get_failed_ssh_attempts,
        "remote_ip":                get_recent_remote_logins,
        "num_cron_jobs":            count_cron_jobs,
        "total_processes":          lambda: pid_count,
        "avg_load":                 get_avg_load,
        "software_installed":       get_installed_software_count,
        "encrypted_files":          get_encrypted_files,
        "usbs":                     collect_usb_info,
        "mac_address": lambda: ':'.join(
                            '{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                            for ele in range(40, -1, -8)
                        ) if uuid.getnode() else "Unknown",
        "ip_addresses":             get_lan_and_internet_ips,
        "sudo_command_failures":    get_recent_sudo_failures,
        "locked_users":             get_account_lockouts,
        "failed_password_changes":  lambda: pw_fail_count,
        "users_failed_password_change": lambda: pw_fail_users,
        "new_users":                get_new_user_creations,
        "deleted_users":            get_user_deletions,
        "modified_users":           get_user_modifications,
        "successful_logins":        get_successful_logins,
        "reverse_shell_events":     detect_reverse_shell_events,
        "kernel_latency":           get_kernel_latency,
        "scheduling_latency":       get_scheduling_latency,
        "realtime_latency":         get_realtime_latency,

        "application_usage":        lambda: list(app_usage_queue.queue),

    }

    # Run collectors in parallel
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
            logging.warning("collect_metrics: timeout in metrics collection")
        finally:
            for key in collectors:
                results.setdefault(key, None)

    # Additional collectors not in parallel block
    try:
        results["login_time"] = check_recent_unlock(tail_lines=1000, window_secs=10)
    except Exception:
        results["login_time"] = None

    try:
        results["command_executions"] = get_command_executions()
    except Exception:
        results["command_executions"] = []

    try:
        results["network_status"] = collect_network_status()
    except Exception:
        results["network_status"] = []

    read_rate, write_rate = get_disk_io_rate()
    results["disk_read_rate"]  = read_rate
    results["disk_write_rate"] = write_rate

    # Deduplicate locked users
    current_locked = set(results["locked_users"]) if results["locked_users"] else set()
    new_locked = current_locked - sent_event_cache["locked_users"]
    sent_event_cache["locked_users"].update(current_locked)

    # Assemble final metrics payload
    metrics = {
        "timestamp":                 now_str,
        "cpu_usage":                 results["cpu_usage"],
        "memory_usage":              results["memory_usage"],
        "ram_usage":                 results["ram_usage"],
        "startup_latency":           results["startup_latency"],
        "per_process_memory":        results["per_process_memory"],
        "disk_read_rate":            results["disk_read_rate"],
        "disk_write_rate":           results["disk_write_rate"],
        "network_bytes_sent":        net_io.bytes_sent,
        "network_bytes_recv":        net_io.bytes_recv,
        "network_packets_sent":      net_io.packets_sent,
        "network_packets_recv":      net_io.packets_recv,
        "active_processes":          results["active_processes"],
        "failed_logins":             results["failed_logins"],
        "failed_logins_by_user":     results["failed_logins_by_user"],
        "failed_logins_by_ip":       results["failed_logins_by_ip"],
        "expired_credential_attempts": results["expired_credential_attempts"],
        "dictionary_attack_signatures": results["dictionary_attack_signatures"],
        "total_threads":             results["total_threads"],
        "open_files":                results["open_files"],
        "num_gui_processes":         results["num_gui_processes"],
        "num_open_windows":          results["num_open_windows"],
        "gpu_usage":                 results["gpu_usage"],
        "system_temperature":        results["system_temperature"],
        "io_wait_time":              results["io_wait_time"],
        "context_switches":          results["context_switches"],
        "response_time":             results["response_time"],
        "username":                  results["username"],
        "failed_ssh_attempts":       results["failed_ssh_attempts"],
        "remote_ip":                 results["remote_ip"],
        "num_cron_jobs":             results["num_cron_jobs"],
        "total_processes":           results["total_processes"],
        "avg_load":                  results["avg_load"],
        "software_installed":        results["software_installed"],
        "encrypted_files":           results["encrypted_files"],
        "sudo_failures":             results["sudo_command_failures"],

        # NEW CLEAN LOCKOUT OUTPUT
        "locked_users":              list(new_locked),
        "account_lockouts":          len(current_locked),

        "new_users":                 results["new_users"],
        "deleted_users":             results["deleted_users"],
        "modified_users":            results["modified_users"],
        "failed_password_changes":   results["failed_password_changes"],
        "users_failed_password_change": results["users_failed_password_change"],
        "command_executions":        results["command_executions"],
        "successful_logins":         results["successful_logins"],
        "application_usage":         results["application_usage"],
        "network_status":            results["network_status"],
        "hostname":                  socket.gethostname(),
        "kernel_latency":           results["kernel_latency"],
        "scheduling_latency":       results["scheduling_latency"],
        "realtime_latency":         results["realtime_latency"],


    }

    # Convert application usage timestamps
    if results.get("application_usage"):
        for record in results["application_usage"]:
            for key in ("start_time", "end_time", "timestamp"):
                if isinstance(record.get(key), datetime):
                    record[key] = record[key].isoformat()

    # Clear the queue
    while not app_usage_queue.empty():
        app_usage_queue.get()

    return metrics


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
                    "deleted_users": data.get("deleted_users"),
                    "modified_users": data.get("modified_users"),
                    "successful_logins": data.get("successful_logins"),
                    # "failed_logins": data.get("failed_logins"),
                    "failed_logins_by_user": data.get("failed_logins_by_user"),
                    # # "failed_logins_by_ip": data.get("failed_logins_by_ip"),
                    # # "failed_ssh_attempts": data.get("failed_ssh_attempts"),
                    # # "failed_password_changes": data.get("failed_password_changes"),
                    # # "account_lockouts": data.get("account_lockouts"),
                    "locked_users": data.get("locked_users"),
                    "application_usage":data.get("application_usage"),
                    "network_status":data.get("network_status"),
                    "kernel_latency": data.get("kernel_latency"),
                    "scheduling_latency": data.get("scheduling_latency"),
                    "realtime_latency": data.get("realtime_latency")

                
                }
                print("Key Metrics:\n" + json.dumps(important_metrics, indent=4) + "\033[0m")
   
            except Exception as e:
                logging.error(f"Kafka send error: {e}")
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()

