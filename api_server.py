from fastapi import FastAPI
from db_connector import get_db_connection
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware 
from collections import defaultdict
import os
import json
import threading
import time
from fastapi import HTTPException
import kafka_consumer.config_consumer as config_consumer



app = FastAPI() # Add CORS middleware

# Ensure table exists at startup
config_consumer.init_data_exfiltration_table()
config_consumer.init_privileged_user_table()
config_consumer.init_anomalous_file_access_table()
config_consumer.init_dormancy_table()
config_consumer.init_bulk_data_operation_table()
config_consumer.init_abnormal_login_logout_table()
config_consumer.init_alert_suppression_table()

app.add_middleware( 
    CORSMiddleware, 
    allow_origins=["*"], # Add your React app origin
    allow_credentials=True, 
    allow_methods=["*"],
    allow_headers=["*"]
)
     

@app.get("/", tags=["Root"])
def read_root():
    return {"message": "API is working!"}

@app.get("/records", tags=["Records"])
def get_all_records():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM anomalies_log")
    records = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in records]
    cursor.close()
    conn.close()
    return result

@app.get("/anomalies/last24hours")
def get_anomalies_last_24_hours():
    conn = get_db_connection()
    cursor = conn.cursor()
    last_24_hours = datetime.now() - timedelta(hours=24)
    cursor.execute(
        "SELECT COUNT(*) FROM anomalies_log WHERE timestamp >= %s;",
        (last_24_hours,)
    )
    count = cursor.fetchone()[0]
    conn.close()
    return {"anomalies_last_24_hours": count}

@app.get("/anomalies/last7days")
def get_anomalies_last_7_days():
    conn = get_db_connection()
    cursor = conn.cursor()
    last_7_days = datetime.now() - timedelta(days=7)
    cursor.execute("SELECT COUNT(*) FROM anomalies_log WHERE timestamp >= %s;", (last_7_days,))
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return {"anomalies_last_7_days": count}


@app.get("/anomalies/last30days")
def get_anomalies_last_30_days():
    conn = get_db_connection()
    cursor = conn.cursor()
    last_30_days = datetime.now() - timedelta(days=30)
    cursor.execute("SELECT COUNT(*) FROM anomalies_log WHERE timestamp >= %s;", (last_30_days,))
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return {"anomalies_last_30_days": count}

@app.get("/anomalies/totalanomalies")
def get_total_anomalies():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM anomalies_log ",    )
    count = cursor.fetchone()[0]
    conn.close()
    return {"total_anomalies": count}

@app.get("/anomalies/totalusers")
def get_total_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(DISTINCT user_id) FROM anomalies_log") 
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return {"total_users": count}

@app.get("/anomalies/totalentities")
def get_total_entities():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(DISTINCT device_mac) FROM anomalies_log") 
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return {"total_entities": count}


@app.get("/anomalies/latest-anomaly")
def get_last_anomaly():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT * FROM anomalies_log ORDER BY timestamp DESC LIMIT 1;")
    row = cursor.fetchone()
    columns = [desc[0] for desc in cursor.description]
    result = dict(zip(columns, row)) if row else {}
    cursor.close()
    conn.close()
    return {"last_anomaly": result}



CONFIG_PATH = os.environ.get("UEBA_CONFIG", "/home/config.json")
with open(CONFIG_PATH, "r") as f:
    _cfg = json.load(f)

# Reverse the event_type mapping: {1: "AUTHENTICATION_EVENTS", ...}
# event_type_map = {str(v): k for k, v in config["mappings"]["event_type"].items()}
event_type_map = {str(v): k for k, v in _cfg["mappings"]["event_type"].items()}

@app.get("/anomalies/daily-count-by-type")
def get_daily_anomalies_by_type():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            DATE(timestamp) AS day,
            event_type,
            COUNT(*) AS count
        FROM anomalies_log
        GROUP BY day, event_type
        ORDER BY day DESC, event_type;
    """)
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]

    cursor.close()
    conn.close()
    return result



@app.get("/api/user-anomaly-summary")
def get_user_anomaly_summary():
    conn = get_db_connection()
    cursor = conn.cursor()

    now = datetime.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    last_30d = now - timedelta(days=30)

    # Fetch anomaly counts per user for 24h, 7d, 30d, and total
    cursor.execute("""
        SELECT user_id,
            COUNT(*) AS total_anomalies,
            SUM(CASE WHEN timestamp >= %s THEN 1 ELSE 0 END) AS anomalies_last_24_hours,
            SUM(CASE WHEN timestamp >= %s THEN 1 ELSE 0 END) AS anomalies_last_7_days,
            SUM(CASE WHEN timestamp >= %s THEN 1 ELSE 0 END) AS anomalies_last_30_days
        FROM anomalies_log
        GROUP BY user_id
    """, (last_24h, last_7d, last_30d))
    summary_rows = cursor.fetchall()

    # Fetch event type counts per user (numeric only)
    cursor.execute("""
        SELECT user_id, event_type, COUNT(*)
        FROM anomalies_log
        GROUP BY user_id, event_type
    """)
    event_type_rows = cursor.fetchall()

    conn.close()

    # Prepare a dict for quick lookup of event type counts
    event_type_data = {}
    for user_id, event_type_id, count in event_type_rows:
        if user_id not in event_type_data:
            event_type_data[user_id] = {}
        event_type_data[user_id][event_type_id] = count  # keep numeric

    # Combine both datasets
    result = []
    for row in summary_rows:
        user_id, total_anomalies, count_24h, count_7d, count_30d = row
        result.append({
            "user_id": user_id,
            "total_anomalies": total_anomalies,
            "anomalies_last_24_hours": count_24h,
            "anomalies_last_7_days": count_7d,
            "anomalies_last_30_days": count_30d,
            "event_type_counts": event_type_data.get(user_id, {})
        })

    return result


@app.get("/api/users-list")
def get_users_list():
    conn = get_db_connection()
    cursor = conn.cursor()

    now = datetime.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    last_30d = now - timedelta(days=30)

    # Fetch anomaly counts per user for total, 24h, 7d, 30d
    cursor.execute("""
        SELECT user_id,
            COUNT(*) AS total_anomalies,
            SUM(CASE WHEN timestamp >= %s THEN 1 ELSE 0 END) AS anomalies_last_24_hours,
            SUM(CASE WHEN timestamp >= %s THEN 1 ELSE 0 END) AS anomalies_last_7_days,
            SUM(CASE WHEN timestamp >= %s THEN 1 ELSE 0 END) AS anomalies_last_30_days
        FROM anomalies_log
        GROUP BY user_id
    """, (last_24h, last_7d, last_30d))
    summary_rows = cursor.fetchall()

    # Fetch event type counts per user (numeric only)
    cursor.execute("""
        SELECT user_id, event_type, COUNT(*)
        FROM anomalies_log
        GROUP BY user_id, event_type
    """)
    event_type_rows = cursor.fetchall()

    # Fetch highest severity log_text per user
    cursor.execute("""
        SELECT a.user_id, a.log_text
        FROM anomalies_log a
        INNER JOIN (
            SELECT user_id, MAX(CAST(severity AS INTEGER)) AS max_severity
            FROM anomalies_log
            GROUP BY user_id
        ) b
        ON a.user_id = b.user_id AND CAST(a.severity AS INTEGER) = b.max_severity
    """)
    log_rows = cursor.fetchall()

    conn.close()

    # Build event_type_counts dict (numeric keys)
    event_type_data = {}
    for user_id, event_type_id, count in event_type_rows:
        if user_id not in event_type_data:
            event_type_data[user_id] = {}
        event_type_data[user_id][event_type_id] = count

    # Build log_text per user
    highest_severity_logs = {user_id: log_text for user_id, log_text in log_rows}

    # Merge everything into result
    result = []
    for row in summary_rows:
        user_id, total_anomalies, count_24h, count_7d, count_30d = row
        result.append({
            "user_id": user_id,
            "total_anomalies": total_anomalies,
            "anomalies_last_24_hours": count_24h,
            "anomalies_last_7_days": count_7d,
            "anomalies_last_30_days": count_30d,
            "event_type_counts": event_type_data.get(user_id, {}),
            "highest_severity_log": highest_severity_logs.get(user_id, "")
        })

    return result



# Fetch All 24hr Anomalies details
@app.get("/anomalies/All-24hr-Anomalies")
def all_24hr_anomalies():

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM anomalies_log WHERE timestamp >= NOW() - INTERVAL '24 hours'")
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result


# Fetch All 7 days Anomalies details
@app.get("/anomalies/All-7days-Anomalies")
def all_7days_anomalies():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM anomalies_log WHERE timestamp >= NOW() - INTERVAL '7 days'")
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result

# Fetch All 30 days Anomalies details
@app.get("/anomalies/All-30days-Anomalies")
def all_30days_anomalies():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM anomalies_log WHERE timestamp >= NOW() - INTERVAL '30 days'")
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result

# Fetch total anomalies count
@app.get("/anomalies/All-Anomalies")
def all_anomalies_count():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM anomalies_log")
    total = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return {"total_anomalies": total}


@app.get("/anomalies/total-user-list")
def get_total_user_list():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            e.user_id,
            e.avg_severity,
            e.anomalies_last_24_hours,
            e.anomalies_last_7_days,
            e.anomalies_last_30_days,
            e.total_events,
            d.total_devices,
            d.device_mac_list,
            t.latest_event_timestamp
        FROM (
            SELECT
                user_id,
                COUNT(*) AS total_events,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') AS anomalies_last_24_hours,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '7 days') AS anomalies_last_7_days,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '30 days') AS anomalies_last_30_days,
                ROUND(AVG(CAST(severity AS INTEGER))) AS avg_severity
            FROM anomalies_log
            WHERE timestamp IS NOT NULL
            GROUP BY user_id
        ) e
        JOIN (
            SELECT
                user_id,
                COUNT(DISTINCT device_mac) AS total_devices,
                ARRAY_AGG(DISTINCT device_mac) AS device_mac_list
            FROM anomalies_log
            WHERE device_mac IS NOT NULL
            GROUP BY user_id
        ) d ON e.user_id = d.user_id
        JOIN (
            SELECT
                user_id,
                MAX(timestamp) AS latest_event_timestamp
            FROM anomalies_log
            WHERE timestamp IS NOT NULL
            GROUP BY user_id
        ) t ON e.user_id = t.user_id
        ORDER BY e.user_id;
        """
    )

    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result



@app.get("/anomalies/total-entity-list")
def get_total_entity_list():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            e.device_mac,
            e.avg_severity,
            e.anomalies_last_24_hours,
            e.anomalies_last_7_days,
            e.anomalies_last_30_days,
            e.total_events,
            u.user_id_list,
            u.total_users,
            t.latest_event_timestamp
        FROM (
            SELECT
                device_mac,
                COUNT(*) AS total_events,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') AS anomalies_last_24_hours,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '7 days') AS anomalies_last_7_days,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '30 days') AS anomalies_last_30_days,
                ROUND(AVG(CAST(severity AS INTEGER))) AS avg_severity
            FROM anomalies_log
            WHERE device_mac IS NOT NULL AND timestamp IS NOT NULL
            GROUP BY device_mac
        ) e
        LEFT JOIN (
            SELECT
                device_mac,
                ARRAY_AGG(DISTINCT user_id) AS user_id_list,
                COUNT(DISTINCT user_id) AS total_users
            FROM anomalies_log
            WHERE device_mac IS NOT NULL
            GROUP BY device_mac
        ) u ON e.device_mac = u.device_mac
        LEFT JOIN (
            SELECT
                device_mac,
                MAX(timestamp) AS latest_event_timestamp
            FROM anomalies_log
            WHERE device_mac IS NOT NULL AND timestamp IS NOT NULL
            GROUP BY device_mac
        ) t ON e.device_mac = t.device_mac
        ORDER BY e.device_mac;
        """
    )

    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result

@app.get("/anomalies/top-5-anomalies")
def get_top_5_anomalies():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT event_type, COUNT(*) as count
        FROM anomalies_log
        GROUP BY event_type
        ORDER BY count DESC
        LIMIT 5;
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    result = []
    for event_type_id, count in rows:
        result.append({"event_type": event_type_id, "count": count})
    return result




################################### USERS TABLE API ###############################################

# Fetch all unique user list
@app.get("/user/unique-user-list")
def get_unique_user_list():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT user_id FROM anomalies_log")
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result


@app.get("/user/user-details/{user_id}")
def get_user_details(user_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. User summary stats
    cursor.execute("""
        SELECT
            user_id,
            ROUND(AVG(CAST(severity AS INTEGER))) AS avg_severity,
            COUNT(*) AS total_events,
            COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') AS anomalies_last_24_hours,
            COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '7 days') AS anomalies_last_7_days,
            COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '30 days') AS anomalies_last_30_days,
            ARRAY_AGG(DISTINCT device_mac) AS device_list
        FROM anomalies_log
        WHERE user_id = %s
        GROUP BY user_id;
    """, (user_id,))
    user_details = cursor.fetchone()
    columns = [desc[0] for desc in cursor.description]
    user_details = dict(zip(columns, user_details)) if user_details else {}

    # 2. Top 4 latest event_type + event_subtype
    cursor.execute("""
        SELECT event_type, event_subtype, timestamp, device_mac
        FROM anomalies_log
        WHERE user_id = %s
        ORDER BY timestamp DESC
        LIMIT 4;
    """, (user_id,))
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    top_4_latest = [dict(zip(columns, row)) for row in rows]

    # 3. Latest event_reason
    cursor.execute("""
        SELECT event_reason, timestamp
        FROM anomalies_log
        WHERE user_id = %s
        ORDER BY timestamp DESC
        LIMIT 1;
    """, (user_id,))
    row = cursor.fetchone()
    columns = [desc[0] for desc in cursor.description]
    latest_event_reason = dict(zip(columns, row)) if row else {}

    # 4. All event_types and their count (numeric event_type only)
    cursor.execute("""
        SELECT event_type, COUNT(*) AS count
        FROM anomalies_log
        WHERE user_id = %s
        GROUP BY event_type
        ORDER BY count DESC;
    """, (user_id,))
    rows = cursor.fetchall()
    all_event_and_its_count = [{"event_type": event_type_id, "count": count} for event_type_id, count in rows]

    cursor.close()
    conn.close()

    return {
        "user_details": user_details,
        "top_4_latest_events": top_4_latest,
        "latest_event_reason": latest_event_reason,
        "all_event_and_its_count": all_event_and_its_count
    }



@app.get("/user/user-details/{user_id}/{range}")
def get_user_details_by_range(user_id: str, range: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Normalize range (accept both 7d and 07d for safety)
    if range in ("24hr", "24h"):
        query = """
        SELECT timestamp, event_type, event_subtype, device_mac
        FROM anomalies_log
        WHERE timestamp >= NOW() - INTERVAL '24 hours' AND user_id = %s
        ORDER BY timestamp DESC
        """
    elif range in ("07d", "7d"):
        query = """
        SELECT timestamp, event_type, event_subtype, device_mac
        FROM anomalies_log
        WHERE timestamp >= NOW() - INTERVAL '7 days' AND user_id = %s
        ORDER BY timestamp DESC
        """
    elif range == "30d":
        query = """
        SELECT timestamp, event_type, event_subtype, device_mac
        FROM anomalies_log
        WHERE timestamp >= NOW() - INTERVAL '30 days' AND user_id = %s
        ORDER BY timestamp DESC
        """
    else:  # "all"
        query = """
        SELECT timestamp, event_type, event_subtype, device_mac
        FROM anomalies_log
        WHERE user_id = %s
        ORDER BY timestamp DESC
        """

    cursor.execute(query, (user_id,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    # Keep numeric IDs for event_type and event_subtype
    result = []
    for timestamp, event_type_id, event_subtype_id, device_mac in rows:
        result.append({
            "timestamp": str(timestamp),
            "event_type": event_type_id,
            "event_subtype": event_subtype_id,
            "device_mac": device_mac
        })

    return result



# Fetch the all anomalies in taday time intervel in a perticular user

@app.get("/user/user-today-anomalies/{user_id}")
def get_user_today_anomaly(user_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        SELECT 
            event_type,
            timestamp
        FROM 
            anomalies_log
        WHERE 
            user_id  = %s
            AND timestamp >= CURRENT_DATE
            AND timestamp < (CURRENT_DATE + INTERVAL '1 day')
        ORDER BY 
            timestamp;
    """

    cursor.execute(query, (user_id,))
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result  


# fetch top 5 user based on the total events
@app.get("/user/top-5-users-by-total-anomaly")
def get_top_5_user_by_total_anomaly():
    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
    SELECT 
        user_id,
        COUNT(*) AS total_events
    FROM 
        anomalies_log
    GROUP BY 
        user_id
    ORDER BY 
        total_events DESC
    LIMIT 5;
    """

    cursor.execute(query)
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result    


# fetch top 5 users and top 3 events or anomalies with its count 
@app.get("/user/top-5-users-top-3-events")
def get_top_users_events():
    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        WITH user_event_counts AS (
            SELECT 
                user_id,
                COUNT(*) AS total_events
            FROM anomalies_log
            GROUP BY user_id
        ),
        top_5_users AS (
            SELECT 
                user_id
            FROM user_event_counts
            ORDER BY total_events DESC
            LIMIT 5
        ),
        user_event_type_counts AS (
            SELECT 
                al.user_id,
                al.event_type,
                COUNT(*) AS event_count
            FROM anomalies_log al
            JOIN top_5_users tu ON al.user_id = tu.user_id
            GROUP BY al.user_id, al.event_type
        ),
        ranked_event_types AS (
            SELECT 
                user_id,
                event_type,
                event_count,
                ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY event_count DESC) AS rn
            FROM user_event_type_counts
        )
        SELECT 
            user_id,
            event_type,
            event_count
        FROM ranked_event_types
        WHERE rn <= 3
        ORDER BY user_id, event_count DESC
    """

    cursor.execute(query)
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    cursor.close()
    conn.close()

    # Process and structure response
    user_events = defaultdict(list)
    for row in rows:
        row_dict = dict(zip(columns, row))
        user_events[row_dict["user_id"]].append({
            "event": row_dict["event_type"],
            "count": row_dict["event_count"]
        })

    response = []
    for user_id, events in user_events.items():
        response.append({
            "user_id": user_id,
            "top_3_events_and_count": events
        })

    return response


@app.get("/anomalies-vs-time")
def get_anomalies_vs_time():
    conn = get_db_connection()
    cursor = conn.cursor()

    now = datetime.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    last_30d = now - timedelta(days=30)

    # Group by hour of the day (00,01,...,23)
    cursor.execute("""
        SELECT EXTRACT(HOUR FROM timestamp)::INT AS hour, COUNT(*) 
        FROM anomalies_log 
        WHERE timestamp >= %s 
        GROUP BY hour 
        ORDER BY hour;
    """, (last_24h,))
    rows_24h = dict(cursor.fetchall())
    print("[DEBUG] /anomalies-vs-time -> 24h rows:", rows_24h)

    cursor.execute("""
        SELECT EXTRACT(HOUR FROM timestamp)::INT AS hour, COUNT(*) 
        FROM anomalies_log 
        WHERE timestamp >= %s 
        GROUP BY hour 
        ORDER BY hour;
    """, (last_7d,))
    rows_7d = dict(cursor.fetchall())
    print("[DEBUG] /anomalies-vs-time -> 7d rows:", rows_7d)

    cursor.execute("""
        SELECT EXTRACT(HOUR FROM timestamp)::INT AS hour, COUNT(*) 
        FROM anomalies_log 
        WHERE timestamp >= %s 
        GROUP BY hour 
        ORDER BY hour;
    """, (last_30d,))
    rows_30d = dict(cursor.fetchall())
    print("[DEBUG] /anomalies-vs-time -> 30d rows:", rows_30d)

    cursor.close()
    conn.close()

    # Build response: for each hour 0–23, get counts or 0 if missing
    result = []
    for h in range(24):
        time_label = f"{h:02d}:00"
        result.append({
            "time": time_label,
            "24h": rows_24h.get(h, 0),
            "7d": rows_7d.get(h, 0),
            "30d": rows_30d.get(h, 0)
        })

    print("[DEBUG] /anomalies-vs-time -> final result:", result[:5], "...")  # first 5 rows
    return result

@app.get("/anomalies-vs-severity")
def get_anomalies_vs_severity():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all risk scores
    cursor.execute("SELECT risk_score FROM anomalies_log;")
    rows = cursor.fetchall()
    scores = [r[0] for r in rows]

    cursor.close()
    conn.close()

    # Initialize buckets
    result = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    # Bucket scores
    for score in scores:
        if score == 0:
            result["INFO"] += 1
        elif 1 <= score < 20:
            result["LOW"] += 1
        elif 20 <= score <= 40:
            result["MEDIUM"] += 1
        elif 41 <= score <= 70:
            result["HIGH"] += 1
        elif 71 <= score <= 100:
            result["CRITICAL"] += 1

    print("[DEBUG] /anomalies-vs-severity -> final result:", result)
    return result


@app.get("/suspicious-users-list")
def get_suspicious_users_list():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Suspicious = user has at least one anomaly with risk_score > 30
    cursor.execute("""
        SELECT DISTINCT user_id, device_mac
        FROM anomalies_log
        WHERE risk_score > 30
    """)
    rows = cursor.fetchall()
    print("[DEBUG] /suspicious-users-list -> raw rows:", rows)

    cursor.close()
    conn.close()

    # Format output for frontend
    result = []
    for user_id, device_mac in rows:
        result.append({
            "name": user_id,
            "machineId": device_mac
        })

    print("[DEBUG] /suspicious-users-list -> final result:", result)
    return result


@app.get("/user-login-behaviour/{user_id}")
def get_user_login_behaviour(user_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Count login events grouped by day for this user
    cursor.execute("""
        SELECT DATE(timestamp) AS day, COUNT(*) 
        FROM user_session_tracking
        WHERE username = %s AND event_type = 'login'
        GROUP BY day
        ORDER BY day;
    """, (user_id,))
    rows = cursor.fetchall()
    print(f"[DEBUG] /user-login-behaviour/{user_id} -> raw rows:", rows)

    cursor.close()
    conn.close()

    # Format output
    result = []
    for day, count in rows:
        # Format day like "Apr 10"
        time_label = day.strftime("%b %d")
        result.append({
            "time": time_label,
            "count": count
        })

    print(f"[DEBUG] /user-login-behaviour/{user_id} -> final result:", result)
    return result


@app.get("/user-resource-usage/{user_id}")
def get_user_resource_usage(user_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Fetch daily averages of CPU, Memory and Load Average
        cursor.execute("""
            SELECT 
                DATE(timestamp) AS day,
                AVG(cpu_percent) AS avg_cpu,
                AVG(memory_percent) AS avg_mem,
                AVG(load_average) AS avg_load
            FROM latency_monitoring
            WHERE username = %s
            GROUP BY day
            ORDER BY day;
        """, (user_id,))
        rows = cursor.fetchall()

        result = []
        for row in rows:
            day, avg_cpu, avg_mem, avg_load = row

            # Compute average resource usage
            resources = (float(avg_cpu or 0) + float(avg_mem or 0) + float(avg_load or 0)) / 3.0

            result.append({
                "time": day.strftime("%b %d"),   # e.g., "Jul 05"
                "resources": round(resources, 2)
            })

        print(f"[DEBUG] /user-resource-usage/{user_id} -> final result: {result}")
        return result

    finally:
        cursor.close()
        conn.close()


@app.get("/user-risk-score/{user_id}")
def get_user_risk_score(user_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT AVG(risk_score)
            FROM anomalies_log
            WHERE user_id = %s
        """, (user_id,))
        
        avg_risk = cursor.fetchone()[0]
        
        if avg_risk is None:
            avg_risk = 0.0
        
        result = {"riskScore": round(avg_risk, 2)}
        print(f"[DEBUG] /user-risk-score/{user_id} -> {result}")
        return result

    finally:
        cursor.close()
        conn.close()


@app.get("/user-activity-type/{user_id}")
def get_user_activity_type(user_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT event_type, COUNT(*) 
        FROM anomalies_log
        WHERE user_id = %s
        GROUP BY event_type
        ORDER BY COUNT(*) DESC;
    """, (user_id,))

    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    result = []
    for row in rows:
        event_type_id = str(row[0])
        event_type_name = event_type_map.get(event_type_id, f"Unknown ({event_type_id})")
        result.append({
            "name": event_type_name,
            "value": row[1]
        })

    print(f"[DEBUG] /user-activity-type/{user_id} -> {result}")
    return result


@app.get("/recent-anomalies")
def get_recent_anomalies():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            user_id,
            device_mac,
            MAX(timestamp) AS last_active,
            MAX(risk_score) AS risk_score
        FROM anomalies_log
        GROUP BY user_id, device_mac
        ORDER BY last_active DESC
        LIMIT 50;
    """)
    rows = cursor.fetchall()

    result = []
    for row in rows:
        user_id, device_mac, last_active, risk_score = row

        # severity mapping based on risk_score
        if risk_score is None:
            severity = "INFO"
        elif risk_score == 0:
            severity = "INFO"
        elif risk_score < 20:
            severity = "LOW"
        elif 20 <= risk_score < 40:
            severity = "MEDIUM"
        elif 40 <= risk_score < 70:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        # anomalies counts
        cursor.execute("""
            SELECT 
                SUM(CASE WHEN timestamp > NOW() - INTERVAL '24 HOURS' THEN 1 ELSE 0 END) AS last24,
                SUM(CASE WHEN timestamp > NOW() - INTERVAL '7 DAYS' THEN 1 ELSE 0 END) AS last7,
                SUM(CASE WHEN timestamp > NOW() - INTERVAL '30 DAYS' THEN 1 ELSE 0 END) AS last30
            FROM anomalies_log
            WHERE user_id = %s;
        """, (user_id,))
        counts = cursor.fetchone()

        result.append({
            "name": user_id if user_id else "unknown",
            "machineId": device_mac if device_mac else "Unknown",
            "lastActive": last_active,
            "severity": severity,
            "riskScore": int(risk_score) if risk_score is not None else 0,
            "anomaliesLast24": counts[0],
            "anomaliesLast7": counts[1],
            "anomaliesLast30": counts[2],
        })

    cursor.close()
    conn.close()

    print("[DEBUG] /recent-anomalies ->", result)
    return result




# ---------------- DATA EXFILTRATION CONFIG APIs ----------------

@app.get("/config/data-exfiltration", tags=["Data Exfiltration Config"])
def api_get_all_data_exfiltration_configs():
    return config_consumer.get_all_data_exfiltration_configs()


@app.get("/config/data-exfiltration/{config_id}", tags=["Data Exfiltration Config"])
def api_get_data_exfiltration_config(config_id: int):
    result = config_consumer.get_data_exfiltration_config(config_id)
    if not result:
        raise HTTPException(status_code=404, detail="Config not found")
    return result


@app.post("/config/data-exfiltration", tags=["Data Exfiltration Config"])
def api_add_data_exfiltration_config(payload: dict):
    config_id = config_consumer.add_data_exfiltration_config(
        payload.get("sensitive_files", []),
        payload.get("sensitive_data_types", []),
        payload.get("sensitive_file_extensions", []),
        payload.get("trusted_ip_ranges", [])
    )
    return {"message": "Config added successfully", "id": config_id}


@app.put("/config/data-exfiltration/{config_id}", tags=["Data Exfiltration Config"])
def api_update_data_exfiltration_config(config_id: int, payload: dict):
    updated = config_consumer.update_data_exfiltration_config(
        config_id,
        payload.get("sensitive_files", []),
        payload.get("sensitive_data_types", []),
        payload.get("sensitive_file_extensions", []),
        payload.get("trusted_ip_ranges", [])
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Config not found or not updated")
    return {"message": "Config updated successfully"}


@app.delete("/config/data-exfiltration/{config_id}", tags=["Data Exfiltration Config"])
def api_delete_data_exfiltration_config(config_id: int):
    deleted = config_consumer.delete_data_exfiltration_config(config_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Config not found or not deleted")
    return {"message": "Config deleted successfully"}


# ---------------- PRIVILEGED USER CONFIG APIs ----------------

@app.get("/config/privileged-users", tags=["Privileged User Config"])
def api_get_all_privileged_user_configs():
    return config_consumer.get_all_privileged_user_configs()


@app.get("/config/privileged-users/{config_id}", tags=["Privileged User Config"])
def api_get_privileged_user_config(config_id: int):
    result = config_consumer.get_privileged_user_config(config_id)
    if not result:
        raise HTTPException(status_code=404, detail="Config not found")
    return result


@app.post("/config/privileged-users", tags=["Privileged User Config"])
def api_add_privileged_user_config(payload: dict):
    config_id = config_consumer.add_privileged_user_config(
        payload.get("privileged_users", [])
    )
    return {"message": "Config added successfully", "id": config_id}


@app.put("/config/privileged-users/{config_id}", tags=["Privileged User Config"])
def api_update_privileged_user_config(config_id: int, payload: dict):
    updated = config_consumer.update_privileged_user_config(
        config_id,
        payload.get("privileged_users", [])
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Config not found or not updated")
    return {"message": "Config updated successfully"}


@app.delete("/config/privileged-users/{config_id}", tags=["Privileged User Config"])
def api_delete_privileged_user_config(config_id: int):
    deleted = config_consumer.delete_privileged_user_config(config_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Config not found or not deleted")
    return {"message": "Config deleted successfully"}


# ---------------- ANOMALOUS FILE ACCESS CONFIG APIs ----------------

@app.get("/config/anomalous-file-access", tags=["Anomalous File Access Config"])
def api_get_all_anomalous_file_access_configs():
    return config_consumer.get_all_anomalous_file_access_configs()


@app.get("/config/anomalous-file-access/{config_id}", tags=["Anomalous File Access Config"])
def api_get_anomalous_file_access_config(config_id: int):
    result = config_consumer.get_anomalous_file_access_config(config_id)
    if not result:
        raise HTTPException(status_code=404, detail="Config not found")
    return result


@app.post("/config/anomalous-file-access", tags=["Anomalous File Access Config"])
def api_add_anomalous_file_access_config(payload: dict):
    config_id = config_consumer.add_anomalous_file_access_config(
        payload.get("sensitive_files", []),
        payload.get("sensitive_file_extensions", [])
    )
    return {"message": "Config added successfully", "id": config_id}


@app.put("/config/anomalous-file-access/{config_id}", tags=["Anomalous File Access Config"])
def api_update_anomalous_file_access_config(config_id: int, payload: dict):
    updated = config_consumer.update_anomalous_file_access_config(
        config_id,
        payload.get("sensitive_files", []),
        payload.get("sensitive_file_extensions", [])
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Config not found or not updated")
    return {"message": "Config updated successfully"}


@app.delete("/config/anomalous-file-access/{config_id}", tags=["Anomalous File Access Config"])
def api_delete_anomalous_file_access_config(config_id: int):
    deleted = config_consumer.delete_anomalous_file_access_config(config_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Config not found or not deleted")
    return {"message": "Config deleted successfully"}


# ---------------- DORMANCY CONFIG APIs ----------------

@app.get("/config/dormancy", tags=["Dormancy Config"])
def api_get_all_dormancy_configs():
    return config_consumer.get_all_dormancy_configs()


@app.get("/config/dormancy/{config_id}", tags=["Dormancy Config"])
def api_get_dormancy_config(config_id: int):
    result = config_consumer.get_dormancy_config(config_id)
    if not result:
        raise HTTPException(status_code=404, detail="Config not found")
    return result


@app.post("/config/dormancy", tags=["Dormancy Config"])
def api_add_dormancy_config(payload: dict):
    config_id = config_consumer.add_dormancy_config(
        payload.get("dormancy_value", 0)
    )
    return {"message": "Config added successfully", "id": config_id}


@app.put("/config/dormancy/{config_id}", tags=["Dormancy Config"])
def api_update_dormancy_config(config_id: int, payload: dict):
    updated = config_consumer.update_dormancy_config(
        config_id,
        payload.get("dormancy_value", 0)
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Config not found or not updated")
    return {"message": "Config updated successfully"}


@app.delete("/config/dormancy/{config_id}", tags=["Dormancy Config"])
def api_delete_dormancy_config(config_id: int):
    deleted = config_consumer.delete_dormancy_config(config_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Config not found or not deleted")
    return {"message": "Config deleted successfully"}

# ---------------- BULK DATA OPERATION CONFIG APIs ----------------

@app.get("/config/bulk-data-operation", tags=["Bulk Data Operation Config"])
def api_get_all_bulk_data_operation_configs():
    return config_consumer.get_all_bulk_data_operation_configs()


@app.get("/config/bulk-data-operation/{config_id}", tags=["Bulk Data Operation Config"])
def api_get_bulk_data_operation_config(config_id: int):
    result = config_consumer.get_bulk_data_operation_config(config_id)
    if not result:
        raise HTTPException(status_code=404, detail="Config not found")
    return result


@app.post("/config/bulk-data-operation", tags=["Bulk Data Operation Config"])
def api_add_bulk_data_operation_config(payload: dict):
    config_id = config_consumer.add_bulk_data_operation_config(
        payload.get("threshold_value", 0.0)
    )
    return {"message": "Config added successfully", "id": config_id}


@app.put("/config/bulk-data-operation/{config_id}", tags=["Bulk Data Operation Config"])
def api_update_bulk_data_operation_config(config_id: int, payload: dict):
    updated = config_consumer.update_bulk_data_operation_config(
        config_id,
        payload.get("threshold_value", 0.0)
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Config not found or not updated")
    return {"message": "Config updated successfully"}


@app.delete("/config/bulk-data-operation/{config_id}", tags=["Bulk Data Operation Config"])
def api_delete_bulk_data_operation_config(config_id: int):
    deleted = config_consumer.delete_bulk_data_operation_config(config_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Config not found or not deleted")
    return {"message": "Config deleted successfully"}


# ---------------- ABNORMAL LOGIN LOGOUT CONFIG APIs ----------------

@app.get("/config/abnormal-login-logout", tags=["Abnormal Login Logout Config"])
def api_get_all_abnormal_login_logout_configs():
    return config_consumer.get_all_abnormal_login_logout_configs()


@app.get("/config/abnormal-login-logout/{config_id}", tags=["Abnormal Login Logout Config"])
def api_get_abnormal_login_logout_config(config_id: int):
    result = config_consumer.get_abnormal_login_logout_config(config_id)
    if not result:
        raise HTTPException(status_code=404, detail="Config not found")
    return result


@app.post("/config/abnormal-login-logout", tags=["Abnormal Login Logout Config"])
def api_add_abnormal_login_logout_config(payload: dict):
    config_id = config_consumer.add_abnormal_login_logout_config(
        payload.get("start_time"),
        payload.get("end_time")
    )
    return {"message": "Config added successfully", "id": config_id}


@app.put("/config/abnormal-login-logout/{config_id}", tags=["Abnormal Login Logout Config"])
def api_update_abnormal_login_logout_config(config_id: int, payload: dict):
    updated = config_consumer.update_abnormal_login_logout_config(
        config_id,
        payload.get("start_time"),
        payload.get("end_time")
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Config not found or not updated")
    return {"message": "Config updated successfully"}


@app.delete("/config/abnormal-login-logout/{config_id}", tags=["Abnormal Login Logout Config"])
def api_delete_abnormal_login_logout_config(config_id: int):
    deleted = config_consumer.delete_abnormal_login_logout_config(config_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Config not found or not deleted")
    return {"message": "Config deleted successfully"}


# ---------------- ALERT SUPPRESSION CONFIG APIs ----------------

@app.get("/config/alert-suppression", tags=["Alert Suppression Config"])
def api_get_all_alert_suppression_configs():
    return config_consumer.get_all_alert_suppression_configs()


@app.get("/config/alert-suppression/{config_id}", tags=["Alert Suppression Config"])
def api_get_alert_suppression_config(config_id: int):
    result = config_consumer.get_alert_suppression_config(config_id)
    if not result:
        raise HTTPException(status_code=404, detail="Config not found")
    return result


@app.post("/config/alert-suppression", tags=["Alert Suppression Config"])
def api_add_alert_suppression_config(payload: dict):
    config_id = config_consumer.add_alert_suppression_config(
        payload.get("usernames", []),
        payload.get("hostnames", []),
        payload.get("ip_ranges", []),
        payload.get("event_frequency_threshold", 0),
        payload.get("event_sources", []),
        payload.get("timestamp_start"),
        payload.get("timestamp_end")
    )
    return {"message": "Config added successfully", "id": config_id}


@app.put("/config/alert-suppression/{config_id}", tags=["Alert Suppression Config"])
def api_update_alert_suppression_config(config_id: int, payload: dict):
    updated = config_consumer.update_alert_suppression_config(
        config_id,
        payload.get("usernames", []),
        payload.get("hostnames", []),
        payload.get("ip_ranges", []),
        payload.get("event_frequency_threshold", 0),
        payload.get("event_sources", []),
        payload.get("timestamp_start"),
        payload.get("timestamp_end")
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Config not found or not updated")
    return {"message": "Config updated successfully"}


@app.delete("/config/alert-suppression/{config_id}", tags=["Alert Suppression Config"])
def api_delete_alert_suppression_config(config_id: int):
    deleted = config_consumer.delete_alert_suppression_config(config_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Config not found or not deleted")
    return {"message": "Config deleted successfully"}

################################### CLIENT STATUS API ###############################################

@app.get("/clients/active-count")
def get_active_clients_count():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM client_status WHERE status='active'")
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return {"active_clients": count}


@app.get("/clients/status-list")
def get_clients_status_list():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT client_id, last_seen, status FROM client_status ORDER BY client_id")
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result


def main(stop_event=None):

    import uvicorn
    import logging
    from pathlib import Path
    from datetime import datetime

    print("\033[1;32m  !!!!!UEBA DASHBOARD API SERVER (UDP) started!!!!!!\033[0m") 

    # Prepare log folder inside ~/ueba_server_log
    USER_HOME = Path.home()
    BASE_LOG_DIR = USER_HOME / "ueba_server_log"
    BASE_LOG_DIR.mkdir(exist_ok=True)

    today = datetime.now().strftime("%d%b")
    dashboard_log = BASE_LOG_DIR / f"ueba_dashboard_api.log_{today}"

    # Configure Uvicorn but suppress default access logging to console
    config = uvicorn.Config(app, host=_cfg.get("ueba_dashboard", {}).get("host", _cfg["udp"]["server_ip"]),
                            port=int(_cfg.get("ueba_dashboard", {}).get("port", 8000)),
                            reload=False, log_config=None)
    server = uvicorn.Server(config)

    # Redirect uvicorn.access to file
    uvicorn_access = logging.getLogger("uvicorn.access")
    fh = logging.FileHandler(dashboard_log, mode="a")
    fh.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
    uvicorn_access.addHandler(fh)
    uvicorn_access.propagate = False   # don’t bubble to console

    if stop_event is None:
        # Standalone run (python api_server.py)
        server.run()
    else:
        # Run inside consumer_main with cooperative shutdown
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()

        # Poll until stop_event is set
        while not stop_event.is_set():
            time.sleep(0.5)

        # Tell uvicorn to shut down
        server.should_exit = True
        thread.join()




if __name__ == "__main__":
    main()