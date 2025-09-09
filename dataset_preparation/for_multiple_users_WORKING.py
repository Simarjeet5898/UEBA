import os
import pandas as pd
from datetime import datetime, timedelta
import random

# Set save path
save_folder = 'datasets/ueba'
os.makedirs(save_folder, exist_ok=True)

# Configuration
usernames = ['UID_122552', 'UID_803629', 'UID_424079']
start_date = datetime(2025, 7, 1)
end_date = datetime(2025, 10, 1)  # exclusive

# Public holidays
public_holidays = {
    datetime(2025, 8, 15),
    datetime(2025, 8, 19),
    datetime(2025, 9, 6),
}

# Function to check if a date should be excluded
def is_excluded_day(d):
    if d.weekday() == 6:  # Sunday
        return True
    elif d.weekday() == 5:  # Saturday
        week = (d.day - 1) // 7 + 1
        return week in (1, 3)
    return False

# Get all valid workdays
valid_days = []
d = start_date
while d < end_date:
    if not is_excluded_day(d) and d not in public_holidays:
        valid_days.append(d)
    d += timedelta(days=1)

# Select one GPU-enabled user
gpu_user = random.choice(usernames)
print(f"User with GPU: {gpu_user}")

# Function to generate session entries for a user
def generate_user_entries(username, valid_days):
    MIN_MIN = 8 * 60 + 30  # 8:30 AM
    MAX_MIN = 10 * 60      # 10:00 AM
    prev_min = random.randint(MIN_MIN, MIN_MIN + 30)

    user_entries = []
    for day in valid_days:
        drift = random.randint(-5, 5)
        today_min = max(MIN_MIN, min(MAX_MIN, prev_min + drift))
        random_seconds = random.randint(0, 59)
        login_time = day.replace(hour=0, minute=0, second=0) + timedelta(minutes=today_min, seconds=random_seconds)

        # Session duration
        session_seconds = random.randint(8 * 3600, 9 * 3600)
        logout_time = login_time + timedelta(seconds=session_seconds)

        # Resource usage
        cpu = round(random.uniform(8.0, 14.0), 1)
        memory = round(random.uniform(65.0, 78.0), 1)
        gpu = round(random.uniform(0.5, 3.0), 1) if username == gpu_user else 0.0

        # Append login entry
        user_entries.append({
            'username': username,
            'event_type': 'login',
            'login_time': login_time,
            'logout_time': '',
            'session_duration_seconds': '',
            'cpu_usage': cpu,
            'memory_usage': memory,
            'gpu_usage': gpu
        })

        # Append logout entry
        user_entries.append({
            'username': username,
            'event_type': 'logout',
            'login_time': login_time,
            'logout_time': logout_time,
            'session_duration_seconds': session_seconds,
            'cpu_usage': cpu,
            'memory_usage': memory,
            'gpu_usage': gpu
        })

        prev_min = today_min

    return user_entries

# Generate entries for all specified usernames
all_entries = []
for username in usernames:
    all_entries.extend(generate_user_entries(username, valid_days))

# Sort all entries by login_time and username for coherence
df = pd.DataFrame(all_entries)
df['login_time'] = pd.to_datetime(df['login_time'])
df['logout_time'] = pd.to_datetime(df['logout_time'], errors='coerce')
df.sort_values(by=['login_time', 'username'], inplace=True)

# Save to CSV
file_path = os.path.join(save_folder, 'ueba_training_dataset.csv')
df.to_csv(file_path, index=False)

print(f"{len(df)} entries saved for {len(usernames)} users to: {file_path}")
