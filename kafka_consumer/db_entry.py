import uuid, json, psycopg2, random
from datetime import datetime, timedelta
from psycopg2.extras import execute_values

CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

DB_CONFIG = {
    'host': config["local_db"]["host"],
    'user': config["local_db"]["user"],
    'password': config["local_db"]["password"],
    'dbname': config["local_db"]["dbname"]
}

# 20 employees with fixed IP/MAC
users = {
    "kamlesh": {"ip": "192.168.107.102", "mac": "a4:5e:60:9b:32:ff"},
    "neha": {"ip": "10.225.40.23", "mac": "3c:5a:9b:7f:12:ab"},
    "sunny": {"ip": "192.168.107.103", "mac": "b2:1d:7c:5f:91:aa"},
    "shambhavi": {"ip": "192.168.107.104", "mac": "cc:9a:77:2f:41:de"},
    "samshe": {"ip": "10.225.40.24", "mac": "11:aa:3b:4f:66:cd"},
    "munmun": {"ip": "192.168.107.105", "mac": "f1:28:bb:9c:34:ef"},
    "amit": {"ip": "192.168.107.106", "mac": "d0:76:4c:91:83:bc"},
    "shubham": {"ip": "192.168.107.107", "mac": "19:8f:21:5e:bb:ac"},
    "sunil": {"ip": "192.168.107.108", "mac": "f8:9a:7e:22:5c:99"},
    "neeraj": {"ip": "10.225.40.25", "mac": "77:bc:1a:92:4c:44"},
    "rahul": {"ip": "192.168.107.109", "mac": "45:22:9c:1d:3e:af"},
    "vikas": {"ip": "192.168.107.110", "mac": "63:7f:aa:5c:4f:12"},
    "simar": {"ip": "192.168.107.111", "mac": "aa:bb:cc:dd:ee:ff"},
    "manish": {"ip": "192.168.107.112", "mac": "12:34:56:78:9a:bc"},
    "pooja": {"ip": "192.168.107.113", "mac": "98:76:54:32:10:ff"},
    "ajay": {"ip": "192.168.107.114", "mac": "de:ad:be:ef:22:11"},
    "meena": {"ip": "192.168.107.115", "mac": "44:55:66:77:88:99"},
    "gopal": {"ip": "192.168.107.116", "mac": "aa:11:bb:22:cc:33"},
    "suresh": {"ip": "192.168.107.117", "mac": "dd:ee:ff:11:22:33"},
    "rekha": {"ip": "192.168.107.118", "mac": "66:77:88:99:aa:bb"},
}

# Possible events
event_choices = [
    ("AUTHENTICATION_EVENTS", "FAILED_LOGIN", "SSH brute force attempt"),
    ("AUTHENTICATION_EVENTS", "SUCCESSFUL_LOGIN", "Normal login"),
    ("AUTHENTICATION_EVENTS", "LOGOFF", "User logged off"),
    ("FILE_AND_OBJECT_ACCESS_EVENTS", "FILE_UPLOAD", "File uploaded to server"),
    ("FILE_AND_OBJECT_ACCESS_EVENTS", "FILE_DOWNLOAD", "Sensitive file downloaded"),
    ("SYSTEM_EVENTS", "PROCESS_STARTED", "Process started by user"),
    ("SYSTEM_EVENTS", "PROCESS_TERMINATED", "Process terminated"),
    ("USER_ACTIVITY_EVENTS", "APPLICATION_INSTALLED", "New application installed"),
    ("USER_ACTIVITY_EVENTS", "APPLICATION_UNINSTALLED", "Application uninstalled"),
]

def generate_anomaly(user, ts):
    event_type_str, event_name_str, reason = random.choice(event_choices)

    event_type = config["event_type"][event_type_str]
    event_subtype = config["event_name"][event_name_str]
    severity = config["mappings"]["severity"]["ALERT"]

    metrics = {
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "cpu_usage": random.uniform(5, 95),
        "memory_usage": random.uniform(20, 95),
        "disk_usage": random.uniform(30, 95),
        "failed_logins": random.randint(0, 5),
        "system_temperature": random.uniform(40, 90),
        "username": user,
        "ip_addresses": [users[user]["ip"]],
        "mac_address": users[user]["mac"],
        "encrypted_files": random.randint(0, 50),
        "sudo_failures": [None, random.choice([0, 1]), None]
    }

    risk_score = min(100, int(
        metrics["cpu_usage"] * 0.2 +
        metrics["memory_usage"] * 0.2 +
        metrics["failed_logins"] * 10
    ))

    return (
        str(uuid.uuid4()),       # event_id
        user,                    # user_id
        ts,                      # timestamp
        event_type,              # event_type (int)
        event_subtype,           # event_subtype (int)
        severity,                # severity (int)
        "203.122.14.98" if event_name_str == "FAILED_LOGIN" else "N/A",
        "N/A",                   # component
        "N/A",                   # resource
        reason,                  # event_reason
        users[user]["ip"],       # device_ip
        users[user]["mac"],      # device_mac
        json.dumps(metrics),     # log_text
        risk_score               # risk_score
    )

# start_date = datetime(2025, 8, 2)
# end_date = datetime(2025, 9, 1)
start_date = datetime(2025, 9, 3)
end_date   = datetime(2025, 9, 3)

anomalies = []
current_date = start_date

while current_date <= end_date:
    if current_date.weekday() != 6:  # skip Sundays
        entries_today = random.randint(20, 40)
        used_times = set()

        for _ in range(entries_today):
            user = random.choice(list(users.keys()))
            # ensure unique timestamp per entry
            while True:
                ts = current_date + timedelta(
                    hours=random.randint(0, 23),
                    minutes=random.randint(0, 59),
                    seconds=random.randint(0, 59)
                )
                key = (user, ts)
                if key not in used_times:
                    used_times.add(key)
                    break
            anomalies.append(generate_anomaly(user, ts))

    current_date += timedelta(days=1)

with psycopg2.connect(**DB_CONFIG) as conn:
    with conn.cursor() as cur:
        insert_query = """
            INSERT INTO anomalies_log (
                event_id, user_id, timestamp, event_type, event_subtype, severity,
                attacker_info, component, resource, event_reason,
                device_ip, device_mac, log_text, risk_score
            ) VALUES %s
        """
        execute_values(cur, insert_query, anomalies)
        conn.commit()
        print(f"Inserted {len(anomalies)} anomalies between {start_date.date()} and {end_date.date()}")
