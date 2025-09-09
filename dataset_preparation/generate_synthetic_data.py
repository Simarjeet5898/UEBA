import pandas as pd
import random
from datetime import datetime, timedelta

users = ['simar', 'arjun', 'priya', 'rahul', 'neha', 'rohit', 'kiran', 'meena', 'vikram', 'sneha',
         'anil', 'ritu', 'rajat', 'ankita', 'varun', 'deepa', 'manish', 'preeti', 'yash', 'swati']
hostnames = [f"{user}-laptop" for user in users]
auth_types = ['local', 'ssh', 'vpn', 'sso']
remote_ips = ['192.168.1.5', '10.0.0.12', '172.16.5.9', '203.0.113.45', '198.51.100.22']  # Some public IPs (suspicious)

rows = []
for _ in range(2000):
    user = random.choice(users)
    hostname = f"{user}-laptop" if random.random() > 0.1 else random.choice(hostnames)  # 10% chance of different device
    auth_type = random.choices(auth_types, weights=[0.6, 0.2, 0.1, 0.1])[0]
    ip = random.choice(remote_ips)

    login_time = datetime.now() - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23), minutes=random.randint(0, 59))
    hour = login_time.hour
    day = login_time.strftime('%A')
    is_weekend = day in ['Saturday', 'Sunday']
    session_duration = random.randint(60, 14400)  # 1 minute to 4 hours

    # ---- ABNORMALITY CONDITIONS ----
    reasons = []

    if hour < 9 or hour > 21:
        reasons.append("odd hour")
    if ip.startswith("203.") or ip.startswith("198."):
        reasons.append("suspicious IP")
    if auth_type in ['vpn', 'ssh'] and random.random() > 0.8:
        reasons.append("rare auth type")
    if session_duration > 10800:  # >3 hours
        reasons.append("long session")
    if is_weekend and random.random() > 0.85:
        reasons.append("weekend access")
    if hostname != f"{user}-laptop":
        reasons.append("unusual device")

    is_abnormal = 1 if reasons else 0

    row = {
        "username": user,
        "login_time": login_time.strftime('%Y-%m-%d %H:%M:%S'),
        "auth_type": auth_type,
        "hostname": hostname,
        "remote_ip": ip,
        "session_duration_seconds": session_duration,
        "hour": hour,
        "day_of_week": day,
        "is_weekend": is_weekend,
        "is_abnormal": is_abnormal
    }

    rows.append(row)

df = pd.DataFrame(rows)
df.to_csv("datasets/synthetic_login_dataset.csv", index=False)
print("!!!! Synthetic data generated !!!!")
