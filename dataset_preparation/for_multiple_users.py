import os
import pandas as pd
from datetime import datetime, timedelta
import random

# Set save path
save_folder = 'datasets/ueba'
os.makedirs(save_folder, exist_ok=True)

# Configuration
num_users = 500
usernames = [f'UID_{i:06d}' for i in range(1, num_users + 1)]
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

# Randomly choose 100 GPU users
gpu_users = set(random.sample(usernames, 100))

# Assign fixed usage bands per user
user_usage_profile = {}
for username in usernames:
    cpu_low = round(random.uniform(8.0, 12.0), 1)
    cpu_high = round(cpu_low + random.uniform(1.0, 3.0), 1)

    mem_low = round(random.uniform(65.0, 75.0), 1)
    mem_high = round(mem_low + random.uniform(2.0, 5.0), 1)

    if username in gpu_users:
        gpu_low = round(random.uniform(0.5, 1.5), 1)
        gpu_high = round(gpu_low + random.uniform(0.5, 2.0), 1)
    else:
        gpu_low = 0.0
        gpu_high = 0.0

    user_usage_profile[username] = {
        'cpu_range': (cpu_low, cpu_high),
        'mem_range': (mem_low, mem_high),
        'gpu_range': (gpu_low, gpu_high)
    }

# Function to generate session entries for a user
def generate_user_entries(username, valid_days):
    MIN_MIN = 8 * 60 # 8:30 AM
    MAX_MIN = 11 * 60      # 10:00 AM
    prev_min = random.randint(MIN_MIN, MIN_MIN + 30)

    usage = user_usage_profile[username]
    user_entries = []

    for day in valid_days:
        drift = random.randint(-5, 5)
        today_min = max(MIN_MIN, min(MAX_MIN, prev_min + drift))
        random_seconds = random.randint(0, 59)
        login_time = day.replace(hour=0, minute=0, second=0) + timedelta(minutes=today_min, seconds=random_seconds)

        session_seconds = random.randint(8 * 3600, 9 * 3600)
        logout_time = login_time + timedelta(seconds=session_seconds)

        cpu = round(random.uniform(*usage['cpu_range']), 1)
        memory = round(random.uniform(*usage['mem_range']), 1)
        gpu = round(random.uniform(*usage['gpu_range']), 1) if usage['gpu_range'][1] > 0 else 0.0

        # Only one entry per session
        user_entries.append({
            'username': username,
            'login_time': login_time,
            'logout_time': logout_time,
            'session_duration_seconds': session_seconds,
            'cpu_usage': cpu,
            'memory_usage': memory,
            'gpu_usage': gpu
        })

        prev_min = today_min

    return user_entries

# Generate dataset
all_entries = []
for idx, username in enumerate(usernames, start=1):
    all_entries.extend(generate_user_entries(username, valid_days))
    if idx % 50 == 0:
        print(f"[TRAINING] Generated data for {idx} users...")

# Create DataFrame and save
df = pd.DataFrame(all_entries)
df['login_time'] = pd.to_datetime(df['login_time'])
df['logout_time'] = pd.to_datetime(df['logout_time'], errors='coerce')
df.sort_values(by=['login_time', 'username'], inplace=True)

file_path = os.path.join(save_folder, 'ueba_training_dataset_500_users.csv')
df.to_csv(file_path, index=False)

print(f"\n {len(df)} entries saved for {len(usernames)} users to: {file_path}")

########################## Testing Dataset #############################


# Function to generate testing entries with optional anomalies
def generate_user_entries_testing(username, valid_days):
    MIN_MIN = 8 * 60       # 8:00 AM
    MAX_MIN = 11 * 60      # 11:00 AM
    prev_min = random.randint(MIN_MIN, MIN_MIN + 30)

    usage = user_usage_profile[username]
    user_entries = []

    for day in valid_days:
        drift = random.randint(-5, 5)
        today_min = max(MIN_MIN, min(MAX_MIN, prev_min + drift))
        random_seconds = random.randint(0, 59)
        login_time = day.replace(hour=0, minute=0, second=0) + timedelta(minutes=today_min, seconds=random_seconds)

        # ✅ Session duration: 7 to 10 hours
        session_seconds = random.randint(7 * 3600, 10 * 3600)
        logout_time = login_time + timedelta(seconds=session_seconds)

        # Normal usage
        cpu = round(random.uniform(*usage['cpu_range']), 1)
        memory = round(random.uniform(*usage['mem_range']), 1)
        gpu = round(random.uniform(*usage['gpu_range']), 1) if usage['gpu_range'][1] > 0 else 0.0

        # 🔥 Introduce anomaly in 3% of entries
        if random.random() < 0.03:
            cpu = round(random.uniform(15.0, 25.0), 1)
            memory = round(random.uniform(85.0, 95.0), 1)
            if usage['gpu_range'][1] > 0:
                gpu = round(random.uniform(5.0, 10.0), 1)

        user_entries.append({
            'username': username,
            'login_time': login_time,
            'logout_time': logout_time,
            'session_duration_seconds': session_seconds,
            'cpu_usage': cpu,
            'memory_usage': memory,
            'gpu_usage': gpu
        })

        prev_min = today_min

    return user_entries

# Testing period: All days in October 2025
test_start_date = datetime(2025, 10, 1)
test_end_date = datetime(2025, 11, 1)

test_valid_days = []
d = test_start_date
while d < test_end_date:
    test_valid_days.append(d)
    d += timedelta(days=1)

# Generate test entries
test_entries = []
for idx, username in enumerate(usernames, start=1):
    test_entries.extend(generate_user_entries_testing(username, test_valid_days))
    if idx % 50 == 0:
        print(f"[TEST] Generated data for {idx} users...")

# Create test DataFrame
test_df = pd.DataFrame(test_entries)
test_df['login_time'] = pd.to_datetime(test_df['login_time'])
test_df['logout_time'] = pd.to_datetime(test_df['logout_time'], errors='coerce')
test_df.sort_values(by=['login_time', 'username'], inplace=True)

# Save test dataset
test_file_path = os.path.join(save_folder, 'ueba_testing_dataset_500_users.csv')
test_df.to_csv(test_file_path, index=False)

print(f"\n🧪 {len(test_df)} test entries saved for {len(usernames)} users to: {test_file_path}")
