from fastapi import FastAPI
from db_connector import get_db_connection
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware 
from collections import defaultdict
import os
import json
import threading
import time

app = FastAPI() # Add CORS middleware

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
    result = []

    for row in rows:
        row_dict = dict(zip(columns, row))
        # Convert event_type number to string if needed
        event_type_id = str(row_dict["event_type"])
        row_dict["event_type"] = event_type_map.get(event_type_id, f"Unknown ({event_type_id})")
        result.append(row_dict)

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

    # Fetch anomaly counts per user for 24h, 7d, 30d
    cursor.execute("""
        SELECT user_id,
            SUM(CASE WHEN timestamp >= %s THEN 1 ELSE 0 END) AS count_24h,
            SUM(CASE WHEN timestamp >= %s THEN 1 ELSE 0 END) AS count_7d,
            SUM(CASE WHEN timestamp >= %s THEN 1 ELSE 0 END) AS count_30d
        FROM anomalies_log
        GROUP BY user_id
    """, (last_24h, last_7d, last_30d))
    summary_rows = cursor.fetchall()

    # Fetch event type counts per user
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
        event_type_name = event_type_map.get(event_type_id, "UNKNOWN")
        if user_id not in event_type_data:
            event_type_data[user_id] = {}
        event_type_data[user_id][event_type_name] = count

    # Combine both datasets
    result = []
    for row in summary_rows:
        user_id, count_24h, count_7d, count_30d = row
        result.append({
            "user_id": user_id,
            "anomalies_last_24h": count_24h,
            "anomalies_last_7d": count_7d,
            "anomalies_last_30d": count_30d,
            "event_type_counts": event_type_data.get(user_id, {})
        })

    return result


@app.get("/api/users-list")
def get_user_anomaly_summary():
    conn = get_db_connection()
    cursor = conn.cursor()

    now = datetime.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    last_30d = now - timedelta(days=30)

    # Fetch anomaly counts per user for 24h, 7d, 30d
    cursor.execute("""
        SELECT user_id,
            SUM(CASE WHEN timestamp >= %s THEN 1 ELSE 0 END) AS count_24h,
            SUM(CASE WHEN timestamp >= %s THEN 1 ELSE 0 END) AS count_7d,
            SUM(CASE WHEN timestamp >= %s THEN 1 ELSE 0 END) AS count_30d
        FROM anomalies_log
        GROUP BY user_id
    """, (last_24h, last_7d, last_30d))
    summary_rows = cursor.fetchall()

    # Fetch event type counts per user
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

    # Build event_type_counts dict
    event_type_data = {}
    for user_id, event_type_id, count in event_type_rows:
        event_type_name = event_type_map.get(str(event_type_id), "UNKNOWN")
        if user_id not in event_type_data:
            event_type_data[user_id] = {}
        event_type_data[user_id][event_type_name] = count

    # Build log_text per user
    highest_severity_logs = {user_id: log_text for user_id, log_text in log_rows}

    # Merge everything into result
    result = []
    for row in summary_rows:
        user_id, count_24h, count_7d, count_30d = row
        result.append({
            "user_id": user_id,
            "anomalies_last_24h": count_24h,
            "anomalies_last_7d": count_7d,
            "anomalies_last_30d": count_30d,
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


# Fatch All 7 days Anomalies details
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


# Fetch All Anomalies details
@app.get("/anomalies/All-Anomalies")
def all_anomalies():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM anomalies_log")
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result


# fatch user list
@app.get("/anomalies/total-user-list")
def get_total_user_list():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            e.user_id,
            e.avg_severity,
            e.events_last_24hr,
            e.events_last_7d,
            e.events_last_30d,
            e.total_events,
            d.total_devices,
            d.device_mac_list,
            t.latest_event_timestamp
        FROM (
            SELECT
                user_id,
                COUNT(*) AS total_events,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') AS events_last_24hr,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '7 days') AS events_last_7d,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '30 days') AS events_last_30d,
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


# fatch entity list
@app.get("/anomalies/total-entity-list")
def get_total_entity_list():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            e.device_mac,
            e.avg_severity,
            e.events_last_24hr,
            e.events_last_7d,
            e.events_last_30d,
            e.total_events,
            u.user_id_list,
            u.total_users,
            t.latest_event_timestamp
        FROM (
            SELECT
                device_mac,
                COUNT(*) AS total_events,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') AS events_last_24hr,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '7 days') AS events_last_7d,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '30 days') AS events_last_30d,
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


# Fetch Top 5 anomaly and its count
@app.get("/anomalies/top-5-anomalies")
def get_top_5_anomalies():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT event_type, COUNT(*) as count
        FROM anomalies_log
        GROUP BY event_type
        ORDER BY count DESC
        LIMIT 5;
        """
    )
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
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


# Fetch details from a particular user
@app.get("/user/user-details/{user_id}")
def get_user_details(user_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. User summary stats
    query = """
        SELECT
            user_id,
            ROUND(AVG(CAST(severity AS INTEGER))) AS avg_severity,
            COUNT(*) AS total_events,
            COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') AS events_last_24hr,
            COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '7 days') AS events_last_7d,
            COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '30 days') AS events_last_30d,
            ARRAY_AGG(DISTINCT device_mac) AS device_mac_list
        FROM anomalies_log
        WHERE user_id = %s
        GROUP BY user_id;
    """
    cursor.execute(query, (user_id,))
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]

    # 2. Top 5 latest event_type + event_subtype
    top_5_event_type_and_event_subtype_query = """
        SELECT event_type, event_subtype, timestamp, device_mac
        FROM anomalies_log
        WHERE user_id = %s
        ORDER BY timestamp DESC
        LIMIT 4;
    """
    cursor.execute(top_5_event_type_and_event_subtype_query, (user_id,))
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    top_5_event_type_and_event_subtype = [dict(zip(columns, row)) for row in rows]

    # 3. Latest event_reason
    latest_event_reason_query = """
        SELECT event_reason, timestamp
        FROM anomalies_log
        WHERE user_id = %s
        ORDER BY timestamp DESC
        LIMIT 1;
    """
    cursor.execute(latest_event_reason_query, (user_id,))
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    latest_event_reason = [dict(zip(columns, row)) for row in rows]

    # 4. All event_types and their count
    all_event_and_its_count_query = """
        SELECT event_type, COUNT(*) AS count
        FROM anomalies_log
        WHERE user_id = %s
        GROUP BY event_type
        ORDER BY count DESC;
    """
    cursor.execute(all_event_and_its_count_query, (user_id,))
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    all_event_and_its_count = [dict(zip(columns, row)) for row in rows]

    cursor.close()
    conn.close()

    return {
        "user_details": result,
        "top_5_event_type_and_event_subtype": top_5_event_type_and_event_subtype,
        "latest_event_reason": latest_event_reason,
        "all_event_and_its_count": all_event_and_its_count
    }



# Fatch the details of a perticular user given by the range
@app.get("/user/user-details/{user_id}/{range}")
def get_user_details_by_range(user_id: str, range: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if range == "24hr":
        query = """
        SELECT timestamp, event_type, event_subtype, device_mac FROM anomalies_log WHERE timestamp >= NOW() - INTERVAL '24 hours' and user_id = %s order by timestamp DESC
        """
    elif range == "07d":
        query = """
        SELECT timestamp, event_type, event_subtype, device_mac FROM anomalies_log WHERE timestamp >= NOW() - INTERVAL '07 days' and user_id = %s order by timestamp DESC
        """
    elif range == "30d":
        query = """
        SELECT timestamp, event_type, event_subtype, device_mac FROM anomalies_log WHERE timestamp >= NOW() - INTERVAL '30 days' and user_id = %s order by timestamp DESC
        """
    else:
        query = """
        SELECT timestamp, event_type, event_subtype, device_mac FROM anomalies_log WHERE user_id = %s order by timestamp DESC
        """
    
    cursor.execute(query, (user_id,))
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
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


# fatch top 5 users and top 3 events or anomalies with its count 
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


# def main():
#     import uvicorn
#     host = _cfg.get("ueba_dashboard", {}).get("host", _cfg["udp"]["server_ip"])
#     port = int(_cfg.get("ueba_dashboard", {}).get("port", 8000))
#     uvicorn.run(app, host=host, port=port, reload=False)

# def main(stop_event=None):
#     import uvicorn
#     host = _cfg.get("ueba_dashboard", {}).get("host", _cfg["udp"]["server_ip"])
#     port = int(_cfg.get("ueba_dashboard", {}).get("port", 8000))

#     config = uvicorn.Config(app, host=host, port=port, reload=False)
#     server = uvicorn.Server(config)

#     if stop_event is None:
#         # Standalone run (python api_server.py)
#         server.run()
#     else:
#         # Run inside consumer_main with cooperative shutdown
#         thread = threading.Thread(target=server.run, daemon=True)
#         thread.start()

#         # Poll until stop_event is set
#         while not stop_event.is_set():
#             time.sleep(0.5)

#         # Tell uvicorn to shut down
#         server.should_exit = True
#         thread.join()

def main(stop_event=None):

    import uvicorn
    import logging
    from pathlib import Path
    from datetime import datetime

    print("\033[1;32m  !!!!!UEBA DSHBOARD API SERVER (UDP) started!!!!!!\033[0m") 

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