import os
import pandas as pd
from datetime import datetime, timedelta
import random

# === Save Path ===
save_folder = 'datasets/user_behaviour_baseline_dataset'
os.makedirs(save_folder, exist_ok=True)

# === Configuration ===
num_users = 500
usernames = [f'UID_{i:06d}' for i in range(1, num_users + 1)]
start_date = datetime(2025, 7, 1)
end_date = datetime(2025, 10, 1)

# === Public Holidays ===
public_holidays = {
    datetime(2025, 8, 15),
    datetime(2025, 8, 19),
    datetime(2025, 9, 6),
}

# === Exclude Days Logic ===
def is_excluded_day(d):
    if d.weekday() == 6:
        return True
    elif d.weekday() == 5:
        week = (d.day - 1) // 7 + 1
        return week in (1, 3)
    return False

# === Valid Working Days ===
valid_days = []
d = start_date
while d < end_date:
    if not is_excluded_day(d) and d not in public_holidays:
        valid_days.append(d)
    d += timedelta(days=1)

# === Test Days ===
test_days = []
d = datetime(2025, 10, 1)
while d < datetime(2025, 11, 1):
    test_days.append(d)
    d += timedelta(days=1)


# === Helper Generators ===
def random_ip():
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def random_mac():
    return ":".join(f"{random.randint(0x00, 0xFF):02x}" for _ in range(6))

# === Global Anomaly Store ===
global_anomalies = set()

# === User Session Generator ===
def generate_user_sessions_clean(username, days, inject_anomalies=False):
    hostname = f"{username}-host"
    source_os = "Linux"
    remote_ip_base = "127.0.1.1"
    lan_ip_base = random_ip()
    auth_type = random.choice(["local", "ssh"])
    active_mac = random_mac()
    mac_list_base = [active_mac, random_mac()]
    sessions = []

    for day in days:
        is_anomaly = False
        login_hour = random.randint(8, 10)
        login_minute = random.randint(0, 59)
        login_time = day.replace(hour=login_hour, minute=login_minute, second=random.randint(0, 59))
        session_sec = random.randint(7 * 3600, 10 * 3600)
        logout_time = login_time + timedelta(seconds=session_sec)
        remote_ip = remote_ip_base
        lan_ip = lan_ip_base
        mac_list = list(mac_list_base)

        if inject_anomalies and random.random() < 0.03:
            is_anomaly = True
            global_anomalies.add((username, day.date()))
            anomaly_type = random.choice(["odd_hours", "short_session", "long_session", "zero_duration", "unknown_ip_mac"])
            if anomaly_type == "odd_hours":
                login_time = day.replace(hour=random.randint(0, 4), minute=random.randint(0, 59), second=random.randint(0, 59))
                logout_time = login_time + timedelta(seconds=session_sec)
            elif anomaly_type == "short_session":
                session_sec = random.randint(60, 3600)
                logout_time = login_time + timedelta(seconds=session_sec)
            elif anomaly_type == "long_session":
                session_sec = random.randint(12 * 3600, 18 * 3600)
                logout_time = login_time + timedelta(seconds=session_sec)
            elif anomaly_type == "zero_duration":
                logout_time = login_time
                session_sec = 0
            elif anomaly_type == "unknown_ip_mac":
                remote_ip = random_ip()
                lan_ip = random_ip()
                mac_list = [random_mac(), random_mac()]

        record = {
            "username": username,
            "login_time": login_time,
            "logout_time": logout_time,
            "session_duration_seconds": session_sec,
            "hostname": hostname,
            "source_os": source_os,
            "remote_ip": remote_ip,
            "lan_ip": lan_ip,
            "auth_type": auth_type,
            "active_mac": mac_list[0],
            "mac_addresses": str(mac_list)
        }

        if inject_anomalies:
            record["is_anomaly"] = is_anomaly

        sessions.append(record)

    return sessions

# === Application Usage Generator ===
def generate_application_usage(username, days, inject_anomalies=False):
    process_list = ["chrome", "firefox", "vim", "bash", "python", "code", "libreoffice", "slack", "zoom", "docker"]
    usage_logs = []

    for day in days:
        daily_processes = random.sample(process_list, k=random.randint(3, 7))
        for proc in daily_processes:
            pid = random.randint(1000, 5000)
            ppid = random.randint(100, 999)
            cmdline = f"/usr/bin/{proc} --flag"
            terminal = random.choice(["tty1", "pts/0", None])
            status = random.choice(["running", "sleeping", "stopped"])
            cpu = round(random.uniform(0.1, 95.0), 2)
            mem = round(random.uniform(0.1, 100.0), 2)
            start_time = day.replace(hour=random.randint(8, 17), minute=random.randint(0, 59))
            duration = random.randint(300, 7200)
            end_time = start_time + timedelta(seconds=duration)
            timestamp = start_time

            record = {
                "username": username,
                "process_name": proc,
                "pid": pid,
                "ppid": ppid,
                "cmdline": cmdline,
                "terminal": terminal,
                "status": status,
                "cpu_percent": cpu,
                "memory_percent": mem,
                "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": end_time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration_secs": duration,
                "timestamp": timestamp
            }

            if inject_anomalies:
                record["is_anomaly"] = cpu > 80 or mem > 90 or proc not in process_list or (username, day.date()) in global_anomalies

            usage_logs.append(record)

    return usage_logs

# === Executed Commands Generator ===
def generate_executed_commands(username, days, inject_anomalies=False):
    commands = ["ls -l", "cat /etc/passwd", "top", "ps aux", "netstat -an", "df -h", "uptime", "whoami", "ping 8.8.8.8", "sudo reboot", "wget", "curl", "nc"]
    suspicious = {"sudo reboot", "wget", "curl", "nc"}
    sources = ["bash", "zsh", "cron", "ssh", "terminal"]
    command_logs = []

    for day in days:
        for _ in range(random.randint(2, 6)):
            cmd = random.choice(commands)
            timestamp = day.replace(hour=random.randint(8, 18), minute=random.randint(0, 59), second=random.randint(0, 59))
            record = {
                "user_id": username,
                "timestamp": timestamp,
                "source": random.choice(sources),
                "command": cmd
            }
            if inject_anomalies:
                record["is_anomaly"] = cmd in suspicious or (username, day.date()) in global_anomalies
            command_logs.append(record)

    return command_logs

# === Resource Usage Generator ===
def generate_resource_usage(username, days, inject_anomalies=False):
    usage_logs = []
    for day in days:
        for _ in range(random.randint(3, 6)):
            cpu = round(random.uniform(1.0, 95.0), 2)
            mem = round(random.uniform(256, 8192), 2)
            timestamp = day.replace(hour=random.randint(8, 18), minute=random.randint(0, 59), second=random.randint(0, 59))
            record = {
                "timestamp": timestamp,
                "username": username,
                "mac_address": random_mac(),
                "ip_address": random_ip(),
                "cpu_percent": cpu,
                "memory_mb": mem
            }
            if inject_anomalies:
                record["is_anomaly"] = cpu > 85 or mem > 7000 or (username, day.date()) in global_anomalies
            usage_logs.append(record)
    return usage_logs

# === Generate & Save All Datasets ===
session_train, session_test = [], []
app_usage_train, app_usage_test = [], []
commands_train, commands_test = [], []
resource_train, resource_test = [], []

for idx, username in enumerate(usernames, 1):
    session_train.extend(generate_user_sessions_clean(username, valid_days, inject_anomalies=False))
    session_test.extend(generate_user_sessions_clean(username, test_days, inject_anomalies=True))
    app_usage_train.extend(generate_application_usage(username, valid_days, inject_anomalies=False))
    app_usage_test.extend(generate_application_usage(username, test_days, inject_anomalies=True))
    commands_train.extend(generate_executed_commands(username, valid_days, inject_anomalies=False))
    commands_test.extend(generate_executed_commands(username, test_days, inject_anomalies=True))
    resource_train.extend(generate_resource_usage(username, valid_days, inject_anomalies=False))
    resource_test.extend(generate_resource_usage(username, test_days, inject_anomalies=True))
    if idx % 50 == 0:
        print(f"[DATA] Processed {idx} users")

# Save datasets
pd.DataFrame(session_train).sort_values(by=["login_time", "username"]).to_csv(
    os.path.join(save_folder, "user_session_tracking_synthetic_training.csv"), index=False)
pd.DataFrame(session_test).sort_values(by=["login_time", "username"]).to_csv(
    os.path.join(save_folder, "user_session_tracking_synthetic_testing.csv"), index=False)
pd.DataFrame(app_usage_train).sort_values(by=["timestamp", "username"]).to_csv(
    os.path.join(save_folder, "application_usage_synthetic_training.csv"), index=False)
pd.DataFrame(app_usage_test).sort_values(by=["timestamp", "username"]).to_csv(
    os.path.join(save_folder, "application_usage_synthetic_testing.csv"), index=False)
pd.DataFrame(commands_train).sort_values(by=["timestamp", "user_id"]).to_csv(
    os.path.join(save_folder, "executed_commands_synthetic_training.csv"), index=False)
pd.DataFrame(commands_test).sort_values(by=["timestamp", "user_id"]).to_csv(
    os.path.join(save_folder, "executed_commands_synthetic_testing.csv"), index=False)
pd.DataFrame(resource_train).sort_values(by=["timestamp", "username"]).to_csv(
    os.path.join(save_folder, "resource_usage_synthetic_training.csv"), index=False)
pd.DataFrame(resource_test).sort_values(by=["timestamp", "username"]).to_csv(
    os.path.join(save_folder, "resource_usage_synthetic_testing.csv"), index=False)

print("All synthetic datasets generated and saved.")
