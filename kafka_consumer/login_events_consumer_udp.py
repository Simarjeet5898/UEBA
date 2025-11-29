"""
User Session Tracking Consumer Script
-------------------------------------

This script consumes and analyzes user session events from a Kafka topic (`login-events`) 
as part of a UEBA (User and Entity Behavior Analytics) framework. It stores all session 
data in a PostgreSQL database and performs behavioral anomaly detection based on both 
rule-based logic and machine learning.

Key Features:
- Consumes login/logout events from Kafka in real-time
- Persists session data to PostgreSQL (`user_session_tracking_ueba` table)
- Detects:
  • Abnormal login behavior (off-hours, unusual IPs, short/long sessions, holiday/weekend logins)
  • Dormant account usage
  • Brute force login attempts
- Supports both rule-based and ML-based anomaly detection (using a pre-trained model)
- Sends verified anomalies to SIEM and/or an anomaly database

Dependencies:
- Kafka Python client
- psycopg2 (PostgreSQL access)
- joblib (for ML model loading)
- pandas
- Logging (standard library)

Usage:
- Automatically begins consuming and processing messages on execution
- Designed to run continuously as a backend component in a UEBA pipeline

Author: []
Date: []
"""

import json
import logging
LOG = logging.getLogger("Login Events Consumer")
import psycopg2

import socket

from datetime import datetime, timedelta
from helper import store_anomaly_to_database_and_siem
from helper import build_abnormal_login_logout_packet, store_siem_ready_packet, build_anomalous_user_session_packet
from dataclasses import asdict

# === UDP Setup ===
CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

UDP_IP = config["udp"]["server_ip"]
# UDP_PORT = config["udp"]["server_port"]
UDP_PORT = 6007

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((UDP_IP, UDP_PORT))


DB_CONFIG = {
    'host': config["local_db"]["host"],
    'user': config["local_db"]["user"],
    'password': config["local_db"]["password"],
    'dbname': config["local_db"]["dbname"]
}

# === In-memory cache for detecting brute force ===
failed_logins = {}

# === Config ===
FAILED_THRESHOLD = 5  # attempts
WINDOW_MINUTES = 5

from datetime import date, timedelta

# Generate all Sundays for 2025
sundays_2025 = []
d = date(2025, 1, 1)
# Move to first Sunday
while d.weekday() != 6:
    d += timedelta(days=1)
while d.year == 2025:
    sundays_2025.append(d.strftime("%Y-%m-%d"))
    d += timedelta(days=7)


DEFAULT_BASELINE = {
    "login_window": (9, 18),
    "session_durations": [28800, 32400],      # 8h, 9h
    "allowed_ips": ["192.168.1.","127.0.0.0","127.0.0.1","127.0.1.1","10.46.1.","10.229.0.0"],
    "holidays": sundays_2025
}

def get_login_logout_baseline():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            SELECT start_time, end_time
            FROM abnormal_login_logout_config_ueba
            ORDER BY updated_at DESC
            LIMIT 1;
        """)
        row = cur.fetchone()
        cur.close()
        conn.close()

        if row and row[0] and row[1]:
            start_hour = row[0].hour
            end_hour = row[1].hour
            baseline = {
                "login_window": (start_hour, end_hour),
                "session_durations": DEFAULT_BASELINE["session_durations"],
                "allowed_ips": DEFAULT_BASELINE["allowed_ips"],
                "holidays": DEFAULT_BASELINE["holidays"],
            }
            print(f"[CONFIG] Using baseline window from DB: ({start_hour}, {end_hour})")
            return baseline
    except Exception as e:
        LOG.error(f"Config fetch failed: {e}")

    # add this line for default case
    print(f"[CONFIG] Using default baseline window: {DEFAULT_BASELINE['login_window']}")
    return DEFAULT_BASELINE

def init_db():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_session_tracking_ueba (
                id SERIAL PRIMARY KEY,
                timestamp TEXT,
                username TEXT,
                event_type TEXT,
                login_time TEXT,
                logout_time TEXT,
                session_duration_seconds INTEGER,
                last_login_time TEXT,
                hostname TEXT,
                source_os TEXT,
                remote_ip TEXT,
                lan_ip TEXT,
                auth_type TEXT,
                active_mac TEXT,
                mac_addresses TEXT,
                public_ip TEXT,
                geo_country TEXT,
                geo_region TEXT,
                geo_city TEXT,
                snapshot_date DATE
            );
        """)

        conn.commit()
        cur.close()
        conn.close()
        print("[DB] user_session_tracking_ueba table ensured on init")

    except Exception as e:
        LOG.error(f"[DB INIT] Failed to create table: {e}")


def user_session_data(event):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # 1. Create table if not exists (original + snapshot_date)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_session_tracking_ueba (
                id SERIAL PRIMARY KEY,
                timestamp TEXT,
                username TEXT,
                event_type TEXT,
                login_time TEXT,
                logout_time TEXT,
                session_duration_seconds INTEGER,
                last_login_time TEXT,
                hostname TEXT,
                source_os TEXT,
                remote_ip TEXT,
                lan_ip TEXT,
                auth_type TEXT,
                active_mac TEXT,
                mac_addresses TEXT,
                public_ip TEXT,
                geo_country TEXT,
                geo_region TEXT,
                geo_city TEXT,
                snapshot_date DATE
            );
        """)

        username = event.get("username")
        hostname = event.get("hostname")
        now_date = datetime.now().date()

        login_time  = event.get("login_time")
        logout_time = event.get("logout_time")
        duration    = event.get("session_duration_seconds")

        # -----------------------------------------------------
        # STEP 1 — CHECK if a row already exists for today
        # -----------------------------------------------------
        cur.execute("""
            SELECT id FROM user_session_tracking_ueba
            WHERE username = %s
              AND hostname = %s
              AND snapshot_date = %s
            ORDER BY id DESC LIMIT 1;
        """, (username, hostname, now_date))

        existing_row = cur.fetchone()

        # -----------------------------------------------------
        # STEP 2 — LOGIN event
        # -----------------------------------------------------
        if event.get("event_type") == "login":

            if existing_row:
                # --> UPDATE same row (reset session)
                cur.execute("""
                    UPDATE user_session_tracking_ueba
                    SET 
                        timestamp = %s,
                        event_type = 'login',
                        login_time = %s,
                        logout_time = NULL,
                        session_duration_seconds = NULL,
                        last_login_time = %s,
                        source_os = %s,
                        remote_ip = %s,
                        lan_ip = %s,
                        auth_type = %s,
                        active_mac = %s,
                        mac_addresses = %s,
                        public_ip = %s,
                        geo_country = %s,
                        geo_region = %s,
                        geo_city = %s
                    WHERE id = %s;
                """, (
                    event.get("timestamp"),
                    login_time,
                    event.get("last_login_time"),
                    event.get("source_os"),
                    event.get("remote_ip", "Unknown"),
                    event.get("lan_ip", "Unknown"),
                    event.get("auth_type", "local"),
                    event.get("active_mac", "Unknown"),
                    json.dumps(event.get("mac_addresses", [])),
                    event.get("public_ip", "Unknown"),
                    event.get("geo_country", "Unknown"),
                    event.get("geo_region", "Unknown"),
                    event.get("geo_city", "Unknown"),
                    existing_row[0]
                ))

            else:
                # --> INSERT NEW ROW for today's first login
                cur.execute("""
                    INSERT INTO user_session_tracking_ueba
                    (timestamp, username, event_type, login_time, logout_time,
                     session_duration_seconds, last_login_time, hostname,
                     source_os, remote_ip, lan_ip, auth_type, active_mac,
                     mac_addresses, public_ip, geo_country, geo_region,
                     geo_city, snapshot_date)
                    VALUES (%s, %s, 'login', %s, NULL,
                            NULL, %s, %s,
                            %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s);
                """, (
                    event.get("timestamp"),
                    username,
                    login_time,
                    event.get("last_login_time"),
                    hostname,
                    event.get("source_os"),
                    event.get("remote_ip", "Unknown"),
                    event.get("lan_ip", "Unknown"),
                    event.get("auth_type", "local"),
                    event.get("active_mac", "Unknown"),
                    json.dumps(event.get("mac_addresses", [])),
                    event.get("public_ip", "Unknown"),
                    event.get("geo_country", "Unknown"),
                    event.get("geo_region", "Unknown"),
                    event.get("geo_city", "Unknown"),
                    now_date
                ))

        # -----------------------------------------------------
        # STEP 3 — LOGOUT event
        # -----------------------------------------------------
        elif event.get("event_type") == "logout":

            cur.execute("""
                UPDATE user_session_tracking_ueba
                SET 
                    logout_time = %s,
                    session_duration_seconds = %s,
                    event_type = 'logout'
                WHERE id = (
                    SELECT id FROM user_session_tracking_ueba
                    WHERE username = %s
                      AND hostname = %s
                      AND snapshot_date = %s
                    ORDER BY id DESC LIMIT 1
                );
            """, (
                logout_time,
                duration,
                username,
                hostname,
                now_date
            ))

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        LOG.error(f"USER Session Tracking Table insert/update error: {e}")


def detect_anomalous_user_session(event, user_baseline):
    """
    UEBA_025 — Rule-Based Anomalous User Session Detection
    ------------------------------------------------------
    This checks completed user sessions (logout events) for anomalies:
    - Abnormal session duration
    - Login outside usual time window
    - IP address abnormality
    - Weekend/Holiday activity
    - Too many short sessions in one day
    """

    # Only process full sessions (logout events)
    if event.get("event_type") != "logout":
        return

    username = event.get("username")
    hostname = event.get("hostname")
    logout_time = event.get("logout_time")
    login_time = event.get("login_time")
    session_duration = event.get("session_duration_seconds")

    if not login_time or not logout_time or not session_duration:
        return

    ts = datetime.fromisoformat(logout_time)
    hour = ts.hour
    date_str = logout_time.split(" ")[0]
    day_of_week = ts.weekday()
    user_ip = event.get("remote_ip", "")

    reasons = []
    risk_score = 0

    # -------------------------------------------------------
    # 1. LOGIN WINDOW CHECK
    # -------------------------------------------------------
    login_window = user_baseline.get("login_window", (9, 18))
    if not (login_window[0] <= hour <= login_window[1]):
        reasons.append(f"Session ended at unusual hour: {hour} (baseline {login_window})")
        risk_score += 3

    # -------------------------------------------------------
    # 2. SESSION DURATION CHECKS
    # -------------------------------------------------------
    typical_durations = user_baseline.get("session_durations", [28800, 32400])
    avg = sum(typical_durations) / len(typical_durations)

    # Too short (e.g., <10min)
    if session_duration < 600:
        reasons.append(f"Very short session ({session_duration}s)")
        risk_score += 2

    # Too long (e.g., > 2hr deviation)
    if abs(session_duration - avg) > 7200:
        reasons.append(
            f"Session duration {session_duration}s deviates significantly from average {int(avg)}s"
        )
        risk_score += 2

    # -------------------------------------------------------
    # 3. WEEKEND / HOLIDAY SESSION
    # -------------------------------------------------------
    holidays = user_baseline.get("holidays", [])
    if day_of_week == 6 or date_str in holidays:
        reasons.append("Session during weekend/holiday")
        risk_score += 4

    # -------------------------------------------------------
    # 4. IP ADDRESS ABNORMALITY
    # -------------------------------------------------------
    allowed_ips = user_baseline.get("allowed_ips", [])
    if allowed_ips and not any(user_ip.startswith(prefix) for prefix in allowed_ips):
        reasons.append(f"Unusual session IP: {user_ip}")
        risk_score += 4

    # -------------------------------------------------------
    # 5. TOO MANY SHORT SESSIONS IN SAME DAY (optional rule)
    # -------------------------------------------------------
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*)
            FROM user_session_tracking_ueba
            WHERE username = %s
              AND snapshot_date = %s
              AND session_duration_seconds IS NOT NULL
              AND session_duration_seconds < 600;
        """, (username, ts.date()))
        
        (short_count,) = cur.fetchone()
        cur.close()
        conn.close()

        if short_count >= 3:
            reasons.append(f"Multiple short sessions detected today ({short_count})")
            risk_score += 3

    except Exception as e:
        LOG.error(f"[AnomalousUserSession] DB lookup failed: {e}")

    # -------------------------------------------------------
    # FINAL DECISION
    # -------------------------------------------------------
    if not reasons:
        return  # no anomaly

    if risk_score < 3:
        return  # below threshold

    # Create anomaly object
    anomaly = {
        "msg_id": "UEBA_SIEM_ANOMALOUS_USER_SESSION_MSG",
        "event_type": "BEHAVIORAL_EVENTS",
        "event_name": "ANOMALOUS_USER_SESSION_DETECTION",
        "event_reason": "; ".join(reasons),
        "timestamp": event.get("timestamp"),
        "log_text": json.dumps(event),
        "severity": "ALERT",
        "session_duration": float(session_duration),
        "attacker_ip_address": user_ip,
        "attacker_username": username,
        "device_hostname": hostname,
        "device_username": username,
        "device_ip_add": user_ip,
        "device_mac_id": event.get("active_mac", "Unknown"),
        "device_type": event.get("source_os", "Unknown"),
    }

    # Store in anomalies DB + SIEM
    store_anomaly_to_database_and_siem(anomaly)

    # Build SIEM packet
    siem_packet = build_anomalous_user_session_packet(anomaly)
    store_siem_ready_packet(asdict(siem_packet))

    LOG.warning(f"[ANOMALOUS USER SESSION] {username} -> {anomaly['event_reason']}")


def detect_abnormal_login_logout(event, user_baseline):
    from datetime import datetime
    import json, logging

    # Decide whether this is login or logout
    timestamp_str = event.get("logout_time") or event.get("login_time")
    action_type = "LOGOUT" if event.get("logout_time") else "LOGIN"

    timestamp = datetime.fromisoformat(timestamp_str)
    hour = timestamp.hour
    date_str = timestamp_str.split(" ")[0]
    day_of_week = timestamp.weekday()

    session_duration = event.get("session_duration_seconds")
    user_ip = event.get("remote_ip", "")
    reasons, risk_score = [], 0

    # 1. LOGIN/LOGOUT WINDOW
    login_window = user_baseline.get("login_window", (8, 13))
    if not (login_window[0] <= hour <= login_window[1]):
        reasons.append(f"{action_type} hour {hour} outside baseline window {login_window}")
        risk_score += 3

    # 2. SESSION DURATION (only makes sense at logout)
    if action_type == "LOGOUT" and session_duration:
        session_durations = user_baseline.get("session_durations", [])
        if session_durations:
            avg_duration = sum(session_durations) / len(session_durations)
            if abs(session_duration - avg_duration) > 7200:
                reasons.append(
                    f"Session duration {session_duration//3600}h unusual (avg: {int(avg_duration)//3600}h)"
                )
                risk_score += 1

    # 3. WEEKEND/HOLIDAY
    holidays = user_baseline.get("holidays", [])
    if day_of_week == 6 or date_str in holidays:
        reasons.append(f"{action_type} on weekend/holiday")
        risk_score += 4

    # 4. IP ADDRESS
    allowed_ips = user_baseline.get("allowed_ips", [])
    if allowed_ips and not any(user_ip.startswith(prefix) for prefix in allowed_ips):
        reasons.append(f"IP {user_ip} not in usual range {allowed_ips}")
        risk_score += 5

    # Result handling
    if reasons:
        analysis_reason = "; ".join(reasons)
        # print(f"Analysis: {analysis_reason} | Risk score: {risk_score}")
        # store_raw_analysis(event, analysis_reason, risk_score)

        ANOMALY_RISK_THRESHOLD = 2
        if risk_score >= ANOMALY_RISK_THRESHOLD:
            if action_type == "LOGIN":
                event_name = "ABNORMAL_LOGIN"
            else:
                event_name = "ABNORMAL_LOGOUT"
            anomaly = {
                "msg_id": "UEBA_SIEM_ABNORMAL_LOGIN_LOGOUT_TIME_MSG",
                "event_type": "BEHAVIORAL_EVENTS",
                "event_name": event_name,
                # "event_name": f"ABNORMAL_{action_type}",
                # "event_name": "ABNORMAL_LOGIN",
                "event_reason": f"Abnormal {action_type.lower()} detected",
                "timestamp": event["timestamp"],
                "log_text": json.dumps(event),
                "severity": "ALERT"
            }
            # Storing in anomalies log because of UI needs it.............
            store_anomaly_to_database_and_siem(anomaly)

            siem_packet = build_abnormal_login_logout_packet(anomaly)
            store_siem_ready_packet(asdict(siem_packet)) 

            # store_siem_ready_packet(siem_packet)
            LOG.warning(f" Abnormal {action_type.lower()} detected: {analysis_reason}")
        else:
            print(f"-> Not escalated (risk score below threshold).")
    else:
        print(f"Analysis: All {action_type.lower()} checks normal.\n")



def detect_dormant_account(event):
    if event.get("event_type") != "login":
        return

    login_time_str = event.get("login_time")
    last_login_time_str = event.get("last_login_time")
    if not login_time_str or not last_login_time_str:
        return

    try:
        login_time = datetime.fromisoformat(login_time_str)
        last_login_time = datetime.fromisoformat(last_login_time_str)
        inactivity_days = (login_time - last_login_time).days

        if inactivity_days >= 30:
            anomaly = {
                "timestamp": event["timestamp"],
                "anomalies": [{
                    "Event Type": "ACCOUNT_ACTIVITY_MONITORING",
                    "Event Sub Type": "DORMANT_ACCOUNT_USED",
                    "Event Details": f"Dormant account accessed after {inactivity_days} days"
                }],
                "metrics": {
                    "username": event["username"],
                    "ip_address": event.get("ip_address", event.get("lan_ip", "Unknown")),
                    "mac_address": event.get("mac_address", "Unknown"),
                    "source": event.get("auth_type", "Unknown"),
                    "hostname": event["hostname"]
                }
            }
            store_anomaly_to_database_and_siem(json.dumps(anomaly))
            LOG.warning(f"Dormant account usage detected: {event['username']} after {inactivity_days} days")

    except Exception as e:
        LOG.error(f"[DormantAccountCheck] Failed: {e}")


def detect_brute_force(event):
    if event["event_type"] != "login_failure":
        return

    key = f"{event['username']}@{event['ip_address']}"
    now = datetime.fromisoformat(event["timestamp"])
    failed_logins.setdefault(key, []).append(now)

    # Filter out old entries
    failed_logins[key] = [
        t for t in failed_logins[key] if (now - t) < timedelta(minutes=WINDOW_MINUTES)
    ]

    if len(failed_logins[key]) >= FAILED_THRESHOLD:
        anomaly = {
            "timestamp": event["timestamp"],
            "anomalies": [{
                "Event Type": "AUTHENTICATION_MONITORING",
                "Event Sub Type": "BRUTE_FORCE_ATTEMPT",
                "Event Details": f"{len(failed_logins[key])} failed login attempts in {WINDOW_MINUTES} minutes"
            }],
            "metrics": {
                "username": event["username"],
                "ip_address": event["ip_address"],
                "hostname": event["hostname"],
                "source": event.get("auth_type", "Unknown"),
            }
        }
        store_anomaly_to_database_and_siem(json.dumps(anomaly))
        LOG.critical(f" Brute force detected for {event['username']}")

        # Clear history to avoid duplicate alerts
        failed_logins[key] = []


def get_statistical_baseline(username, min_samples=10):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # fetch last N login/logout times for this user
        cur.execute("""
            SELECT login_time, logout_time
            FROM user_session_tracking_ueba
            WHERE username = %s
            AND login_time IS NOT NULL  
            ORDER BY id DESC
            LIMIT 50;
        """, (username,))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        if len(rows) < min_samples:
            print(f"[BASELINE] Not enough history for {username}, falling back to config/default.")
            return get_login_logout_baseline()

        # extract login/logout hours
        login_hours = []
        logout_hours = []
        for login_str, logout_str in rows:
            if login_str:
                login_hours.append(datetime.fromisoformat(login_str).hour)
            if logout_str:
                logout_hours.append(datetime.fromisoformat(logout_str).hour)

        if not login_hours or not logout_hours:
            return get_login_logout_baseline()

        # calculate average ±1h window
        start_hour = max(0, int(sum(login_hours)/len(login_hours)) - 1)
        end_hour   = min(23, int(sum(logout_hours)/len(logout_hours)) + 1)

        baseline = {
            "login_window": (start_hour, end_hour),
            "session_durations": DEFAULT_BASELINE["session_durations"],
            "allowed_ips": DEFAULT_BASELINE["allowed_ips"],
            "holidays": DEFAULT_BASELINE["holidays"],
        }
        print(f"[BASELINE] Learned from history for {username}: {baseline['login_window']}")
        return baseline

    except Exception as e:
        LOG.error(f"Baseline learning failed: {e}")
        return get_login_logout_baseline()


# def main():
def main(stop_event=None):
    print("\033[1;32m  !!!!!!!!!!!  Login Events consumer running (UDP)  !!!!!!!!!!!!!!\033[0m")
    LOG.info("!!!!!!!!!!! Login Events consumer running (UDP) !!!!!!!!!!!")
    
    init_db() 
    # ensure_raw_analysis_log_exists()
    try:
        # while True:
        while not (stop_event and stop_event.is_set()):
            data, addr = sock.recvfrom(65535)  # listen for UDP packets
            event = json.loads(data.decode("utf-8"))

            #  Only process login-events
            if event.get("topic") != "login-events":
                continue
            
            LOG.info(
                "[LoginEvent] user=%s type=%s ip=%s host=%s",
                event.get("username"),
                event.get("event_type"),
                event.get("remote_ip") or event.get("lan_ip"),
                event.get("hostname"),
            )
            print(f"\n[CONSUMED EVENT from {addr}]\n{json.dumps(event, indent=2)}")

            user_session_data(event)
            # user_baseline = get_login_logout_baseline()
            user_baseline = get_statistical_baseline(event.get("username"))
            detect_abnormal_login_logout(event, user_baseline)
            detect_anomalous_user_session(event, user_baseline)

            detect_dormant_account(event)
            # detect_brute_force(event)

    except KeyboardInterrupt:
        LOG.info("UDP consumer stopped by user.")
    except Exception as e:
        LOG.error(f"UDP consumer error: {e}")
    finally:
        sock.close()
        LOG.info("UDP socket closed.")



if __name__ == "__main__":
    main()
