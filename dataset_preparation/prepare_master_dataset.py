import os
import sys
import json
import pandas as pd
from datetime import datetime
from sqlalchemy import create_engine

# === Setup project root in path ===
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")

# === Load config ===
with open("config/config.json", "r") as f:
    config = json.load(f)

# === PostgreSQL connection setup ===
DB_URI = f"postgresql://{config['db']['user']}:{config['db']['password']}@{config['db']['host']}/{config['db']['dbname']}"
print("🔌 Connecting to DB:", DB_URI)
engine = create_engine(DB_URI)

# === Define source tables and queries ===
table_queries = {
    "login_events": """
        SELECT username, login_time AS timestamp, 'LOGIN_EVENT' AS event_type,
               auth_type AS details, hostname, remote_ip AS ip_address
        FROM login_events
        WHERE event_type = 'login'
    """,

    "executed_commands": """
        SELECT user_id AS username, timestamp, 'CMD_EXECUTED' AS event_type,
               command AS details, source AS hostname, NULL AS ip_address
        FROM executed_commands
    """,

    "connected_entities": """
        SELECT username, timestamp, 'USB_EVENT' AS event_type,
               vendor_name || ' ' || product_name || ' (SN: ' || serial_number || ')' AS details,
               hostname, mac_address AS ip_address
        FROM connected_entities
    """,

    "file_system_monitoring": """
        SELECT username, timestamp, 'FILE_EVENT' AS event_type,
               directory || ' [' || event_type || ']' AS details,
               hostname, mac_address AS ip_address
        FROM file_system_monitoring
    """,

    "resource_usage": """
        SELECT username, timestamp, 'RESOURCE_USAGE' AS event_type,
               'TopProc: ' || top_process_name || ', RSS: ' || top_process_rss || ', IPs: ' || ip_addresses AS details,
               'N/A' AS hostname, mac_address AS ip_address
        FROM resource_usage
    """
}


# === Build Master Dataset ===
print("\n📦 Collecting data for Master Dataset...")
frames = []

for table, query in table_queries.items():
    try:
        df = pd.read_sql(query, engine)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        frames.append(df)
        print(f"✅ {table}: {len(df)} records")
    except Exception as e:
        print(f"⚠️ Error reading {table}: {e}")

if frames:
    master_df = pd.concat(frames, ignore_index=True)
    master_df = master_df.sort_values("timestamp")

    output_dir = "datasets"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "master_ueba_dataset.csv")
    master_df.to_csv(output_path, index=False)

    print(f"\n✅ Master dataset saved to: {output_path}")
    print(f"📊 Total rows: {len(master_df)}")
else:
    print("❌ No data loaded. Master dataset not created.")
