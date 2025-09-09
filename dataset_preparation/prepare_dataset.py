import os
import sys
import json
import pandas as pd
from datetime import datetime
from sqlalchemy import create_engine

# === Setup project root in path ===
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")

# === Import shared helpers and DB connection ===
import db_connector

# === Load config if needed ===
with open("config/config.json", "r") as f:
    config = json.load(f)

# print("🔍 Config keys:", config.keys())
# print("🔍 Full config content:\n", json.dumps(config, indent=2))

# === PostgreSQL connection setup ===
DB_URI = f"postgresql://{config['db']['user']}:{config['db']['password']}@{config['db']['host']}/{config['db']['dbname']}"
print("🔍 DB_URI:", DB_URI)

engine = create_engine(DB_URI)

# === Fetch raw login events ===
query = """
    SELECT username, login_time, auth_type, hostname, remote_ip, session_duration_seconds
    FROM login_events
    WHERE event_type = 'login';
"""

df = pd.read_sql(query, engine)

# === Feature Extraction ===
df['login_time'] = pd.to_datetime(df['login_time'])
df['hour'] = df['login_time'].dt.hour
df['day_of_week'] = df['login_time'].dt.day_name()
df['is_weekend'] = df['login_time'].dt.weekday >= 5

# === (Optional) Add is_abnormal label for now using static rule ===
df['is_abnormal'] = df['hour'].apply(lambda h: 1 if h < 9 or h > 21 else 0)

# === Save dataset as CSV ===
output_dir = "datasets"
os.makedirs(output_dir, exist_ok=True)
csv_path = os.path.join(output_dir, "abnormal_login_dataset.csv")
df.to_csv(csv_path, index=False)

print(f"✅ Dataset saved to {csv_path}")
