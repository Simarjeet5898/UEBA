import os
import pandas as pd
from datetime import datetime, timedelta
import random

# Save path
save_folder = 'datasets/ueba'
os.makedirs(save_folder, exist_ok=True)

# Configuration
num_users = 500
usernames = [f'UID_{i:06d}' for i in range(1, num_users + 1)]
start_date = datetime(2025, 7, 1)
end_date = datetime(2025, 10, 1)

# Public holidays
public_holidays = {
    datetime(2025, 8, 15),
    datetime(2025, 8, 19),
    datetime(2025, 9, 6),
}

# Exclude days logic
def is_excluded_day(d):
    if d.weekday() == 6:
        return True  # Sunday
    elif d.weekday() == 5:
        week = (d.day - 1) // 7 + 1
        return week in (1, 3)  # 1st and 3rd Saturday
    return False

# Generate valid working days
valid_days = []
d = start_date
while d < end_date:
    if not is_excluded_day(d) and d not in public_holidays:
        valid_days.append(d)
    d += timedelta(days=1)

# Helpers for fake IP and MAC generation
def random_ip():
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def random_mac():
    return ":".join(f"{random.randint(0x00, 0xFF):02x}" for _ in range(6))

# Generate session data

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
        login_hour = random.randint(8, 10)
        login_minute = random.randint(0, 59)
        login_time = day.replace(hour=login_hour, minute=login_minute, second=random.randint(0, 59))
        session_sec = random.randint(7 * 3600, 10 * 3600)
        logout_time = login_time + timedelta(seconds=session_sec)

        remote_ip = remote_ip_base
        lan_ip = lan_ip_base
        mac_list = list(mac_list_base)

        if inject_anomalies and random.random() < 0.03:
            anomaly_type = random.choice([
                "odd_hours", "short_session", "long_session", "zero_duration", "unknown_ip_mac"
            ])

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

        sessions.append({
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
        })

    return sessions

# Generate training data
training_entries = []
for idx, username in enumerate(usernames, 1):
    training_entries.extend(generate_user_sessions_clean(username, valid_days, inject_anomalies=False))
    if idx % 50 == 0:
        print(f"[TRAINING] Processed {idx} users")

training_df = pd.DataFrame(training_entries)
training_df.sort_values(by=["login_time", "username"], inplace=True)
training_df.to_csv(os.path.join(save_folder, "user_session_tracking_synthetic_training.csv"), index=False)

# Generate testing days
test_days = []
d = datetime(2025, 10, 1)
while d < datetime(2025, 11, 1):
    test_days.append(d)
    d += timedelta(days=1)

# Generate testing data
test_entries = []
for idx, username in enumerate(usernames, 1):
    test_entries.extend(generate_user_sessions_clean(username, test_days, inject_anomalies=True))
    if idx % 50 == 0:
        print(f"[TEST] Processed {idx} users")

test_df = pd.DataFrame(test_entries)
test_df.sort_values(by=["login_time", "username"], inplace=True)
test_df.to_csv(os.path.join(save_folder, "user_session_tracking_synthetic_testing.csv"), index=False)

print("\n Training and testing datasets saved successfully.")
