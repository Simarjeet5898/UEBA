import os
import pandas as pd
from datetime import datetime, timedelta
import random

# Set save path
save_folder = 'datasets/ueba'
os.makedirs(save_folder, exist_ok=True)

# Date range
start_date = datetime(2025, 7, 1)
end_date = datetime(2025, 10, 1)  # exclusive

# Public holidays
public_holidays = {
    datetime(2025, 8, 15),
    datetime(2025, 8, 19),
    datetime(2025, 9, 6),
}

# Skip 1st & 3rd Saturdays and all Sundays
def is_excluded_day(d):
    if d.weekday() == 6:
        return True  # All Sundays
    elif d.weekday() == 5:  # Saturday
        week = (d.day - 1) // 7 + 1
        return week in (1, 3)  # 1st and 3rd Saturdays
    return False


# Valid workdays
valid_days = []
d = start_date
while d < end_date:
    if not is_excluded_day(d) and d not in public_holidays:
        valid_days.append(d)
    d += timedelta(days=1)

# Generate alternating login/logout
MIN_MIN = 8 * 60 + 30  # 8:30 AM
MAX_MIN = 10 * 60      # 10:00 AM
prev_min = random.randint(MIN_MIN, MIN_MIN + 30)

entries = []

for day in valid_days:
    drift = random.randint(-5, 5)
    today_min = max(MIN_MIN, min(MAX_MIN, prev_min + drift))
    login_time = day.replace(hour=0, minute=0, second=0) + timedelta(minutes=today_min)

    # Session duration
    session_seconds = random.randint(8 * 3600, 9 * 3600)
    logout_time = login_time + timedelta(seconds=session_seconds)

    # Resource usage
    cpu = round(random.uniform(8.0, 14.0), 1)
    memory = round(random.uniform(65.0, 78.0), 1)
    gpu = 0.0

    # Login entry
    entries.append({
        'username': 'UID_302117',
        'event_type': 'login',
        'login_time': login_time.strftime('%Y-%m-%d %H:%M:%S'),
        'logout_time': '',
        'session_duration_seconds': '',
        'cpu_usage': cpu,
        'memory_usage': memory,
        'gpu_usage': gpu
    })

    # Logout entry
    entries.append({
        'username': 'UID_302117',
        'event_type': 'logout',
        'login_time': login_time.strftime('%Y-%m-%d %H:%M:%S'),
        'logout_time': logout_time.strftime('%Y-%m-%d %H:%M:%S'),
        'session_duration_seconds': session_seconds,
        'cpu_usage': cpu,
        'memory_usage': memory,
        'gpu_usage': gpu
    })

    prev_min = today_min


# Save
df = pd.DataFrame(entries)
file_path = os.path.join(save_folder, 'ueba_training_dataset.csv')
df.to_csv(file_path, index=False)

print(f"{len(df)} Training data saved to: {file_path}")
