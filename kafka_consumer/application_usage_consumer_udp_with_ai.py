"""
Application Usage Monitoring Consumer

This script listens to the Kafka topic 'system-metrics' to consume application usage
events emitted by a producer function (e.g., `track_application_usage()`) running on
endpoint machines. It logs each application launch and exit event into a PostgreSQL
database, supporting later analysis for UEBA_11 (Application Usage Monitoring).

Kafka Topic:
    - system-metrics

Database Table:
    - application_usage

Schema:
    - username, process_name, pid, ppid, cmdline, terminal, status
    - cpu_percent, memory_percent, start_time, end_time, duration_secs, timestamp

 What Gets Logged:
    - User-launched desktop and terminal applications
    - Apps installed via Snap, AppImage, Flatpak, or located in:
        • /snap/
        • /opt/
        • /usr/bin/
    - Applications whose executables match a known list (`INSTALLED_EXEC_NAMES`)
    - Long-running apps with measurable CPU/memory usage (above 0.5%)

 What Is Filtered Out:
    - System/background processes (e.g., cron, systemd, sshd, dbus)
    - Known subprocesses or helper processes of browsers/editors, e.g.:
        • crashpad_handler
        • tsserver.js
        • WebExtensions
        • Socket Process
    - Transient or short-lived apps that exit before the polling interval
    - Kernel-space tasks and processes with missing usernames
    - Non-user apps whose executables don’t match heuristics or known paths

How It Works:
    - The producer scans active processes at regular intervals (default: 5s)
    - Application `launch` events are logged when new matching processes appear
    - Application `exit` events are detected when processes disappear
    - Duration is calculated based on first and last seen timestamps
    - CPU and memory metrics are tracked to determine active/inactive state

Limitations:
    - Frequency analysis and anomaly detection are not performed here (can be added externally)
    - Detection accuracy depends on polling frequency and process visibility
    - Some short-lived apps may not be captured if they terminate too quickly

Preconditions:
    - Kafka producer agent must be installed and running on endpoint
    - PostgreSQL server must be accessible with correct schema
    - System-metrics topic must be active and receiving application usage data

Author: [Your Name or Team]
Date: [Insert Date]
"""


import psycopg2
# from kafka import KafkaConsumer
import socket
import logging
from datetime import datetime
# import uuid 
from helper import store_anomaly_to_database_and_siem, build_anomalous_application_usage_packet, store_siem_ready_packet
# from udp_dispatcher import queues
from dataclasses import asdict
import warnings
from typing import Dict, Any, Tuple, List
import os
import numpy as np
import pandas as pd
import joblib
LOG = logging.getLogger("Application Usage Consumer")
# LOG.setLevel(logging.INFO)  
import json

warnings.filterwarnings("ignore")

os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"  # suppress TF INFO/WARN/most ERROR logs
import tensorflow as tf


CONFIG_PATH = "/home/config.json"
# CONFIG_PATH = "/home/simar/Documents/UEBA_BACKEND/config/config.json"
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

# UDP_IP = config["udp"]["server_ip"]
# UDP_PORT = config["udp"]["server_port"]
UDP_IP = config["udp"]["server_ip"]

# Application consumer internal port
UDP_PORT = 6001  

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((UDP_IP, UDP_PORT))


DB_CONFIG = {
    'host': config["local_db"]["host"],
    'user': config["local_db"]["user"],
    'password': config["local_db"]["password"],
    'dbname': config["local_db"]["dbname"]
}

# ==== AI imports & paths (add below imports) ====


# Base dir -> UEBA_BACKEND
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "ai_models", "anomalous_app_usage")

# Artifact paths
SCALER_PATH    = os.path.join(MODEL_DIR, "scaler.pkl")
PCA_PATH       = os.path.join(MODEL_DIR, "pca.pkl")
ISO_PATH       = os.path.join(MODEL_DIR, "isolation_forest.pkl")
AE_PATH        = os.path.join(MODEL_DIR, "autoencoder.h5")
FEATURES_PATH  = os.path.join(MODEL_DIR, "feature_list.json")
ENCODERS_PATH  = os.path.join(MODEL_DIR, "encoders.json")
THRESHOLD_PATH = os.path.join(MODEL_DIR, "threshold.json")
# ==== end AI imports & paths ====

# ==== AI feature builder + loader + predictor ====
from typing import Optional

# Cache so we don't reload models on every record
_AI_CACHE: Dict[str, Any] = {}

class FeatureBuilder:
    def __init__(self):
        self.vocabs: Dict[str, Dict[str, int]] = {}
        self.freq_maps: Dict[str, Dict[str, float]] = {}
        self.feature_cols_: List[str] = []

    @staticmethod
    def load(path: str) -> "FeatureBuilder":
        with open(path, "r") as f:
            payload = json.load(f)
        fb = FeatureBuilder()
        fb.vocabs = payload.get("vocabs", {})
        fb.freq_maps = payload.get("freq_maps", {})
        fb.feature_cols_ = payload.get("feature_cols", [])
        return fb

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()

        # parse datetimes
        for col in ("start_time", "end_time", "timestamp"):
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors="coerce")

        # duration (secs)
        if "duration_secs" not in df.columns:
            df["duration_secs"] = (df.get("end_time") - df.get("start_time")).dt.total_seconds()
        df["duration_secs"] = pd.to_numeric(df["duration_secs"], errors="coerce").fillna(0)

        # time features
        time_source = "timestamp" if "timestamp" in df.columns else "start_time"
        df["hour"] = df[time_source].dt.hour.fillna(0).astype(int)
        df["hour_sin"] = np.sin(2 * np.pi * df["hour"] / 24.0)
        df["hour_cos"] = np.cos(2 * np.pi * df["hour"] / 24.0)

        # cmdline features
        if "cmdline" in df.columns:
            df["cmdline_len"] = df["cmdline"].astype(str).apply(len)
            df["cmdline_args"] = df["cmdline"].astype(str).apply(lambda x: x.count(" "))
        else:
            df["cmdline_len"] = 0
            df["cmdline_args"] = 0

        # frequency encodings
        for col, fmap in self.freq_maps.items():
            if col in df.columns:
                df[f"{col}_freq"] = df[col].astype(str).map(fmap).fillna(0.0)
            else:
                df[f"{col}_freq"] = 0.0

        # label encodings
        for col, vocab in self.vocabs.items():
            if col in df.columns:
                df[f"{col}_enc"] = df[col].astype(str).map(vocab).fillna(vocab.get("NA", 0)).astype(int)
            else:
                df[f"{col}_enc"] = 0

        # ensure required columns
        for c in self.feature_cols_:
            if c not in df.columns:
                df[c] = 0

        return df[self.feature_cols_].astype(float)

def _load_artifacts():
    if _AI_CACHE:
        return _AI_CACHE
    try:
        scaler = joblib.load(SCALER_PATH)
        pca = joblib.load(PCA_PATH)           # may be None if not used in training
        iso  = joblib.load(ISO_PATH)
        ae   = tf.keras.models.load_model(AE_PATH, compile=False)
        with open(FEATURES_PATH, "r") as f:
            feature_cols = json.load(f)
        fb = FeatureBuilder.load(ENCODERS_PATH)
        with open(THRESHOLD_PATH, "r") as f:
            th = json.load(f)
        threshold = float(th["composite_threshold"])
        _AI_CACHE.update(dict(fb=fb, feature_cols=feature_cols, scaler=scaler, pca=pca, iso=iso, ae=ae, threshold=threshold))
    except Exception as e:
        LOG.exception(f"[AI] Failed to load artifacts: {e}")
        _AI_CACHE.update(dict(error=e))
    return _AI_CACHE

def predict_anomalous_application_usage(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns a dict with AI scores and decision:
      { 'ai_iso_score', 'ai_ae_recon_error', 'ai_composite_score', 'ai_is_anomalous' }
    """
    cache = _load_artifacts()
    if "error" in cache:
        return {"ai_error": str(cache["error"]), "ai_is_anomalous": 0}

    fb         = cache["fb"]
    feature_cols = cache["feature_cols"]
    scaler     = cache["scaler"]
    pca        = cache["pca"]
    iso        = cache["iso"]
    ae         = cache["ae"]
    threshold  = cache["threshold"]

    df = pd.DataFrame([record])
    X = fb.transform(df)                      # features as DataFrame
    # keep column order as in training
    X = X[feature_cols].values

    X_scaled = scaler.transform(X)
    if pca is not None:
        try:
            X_proj = pca.transform(X_scaled)
        except Exception:
            X_proj = X_scaled
    else:
        X_proj = X_scaled

    # IsolationForest score (higher => more anomalous after negation)
    iso_score = -iso.decision_function(X_proj)
    # min-max normalize to [0,1]
    iso_score = (iso_score - iso_score.min()) / (iso_score.max() - iso_score.min() + 1e-12)

    # Autoencoder reconstruction error on scaled input
    recon = ae.predict(X_scaled, verbose=0)
    mse = np.mean(np.square(recon - X_scaled), axis=1)
    ae_score = (mse - mse.min()) / (mse.max() - mse.min() + 1e-12)

    composite = (iso_score + ae_score) / 2.0
    return {
        "ai_iso_score": float(iso_score[0]),
        "ai_ae_recon_error": float(ae_score[0]),
        "ai_composite_score": float(composite[0]),
        "ai_is_anomalous": int(composite[0] >= threshold),
    }
# ==== end AI block ====


# ─── Ensure application_usage table exists ───

def ensure_table(conn):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS application_usage (
            id SERIAL PRIMARY KEY,
            username TEXT,
            process_name TEXT,
            pid INTEGER,
            ppid INTEGER,
            cmdline TEXT,
            terminal TEXT,
            status TEXT,
            cpu_percent REAL,
            memory_percent REAL,
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            duration_secs REAL,
            timestamp TIMESTAMP
        );
    """)
    conn.commit()
    cur.close()

############


def create_latency_monitoring_table(conn):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS latency_monitoring (
            id SERIAL PRIMARY KEY,
            username TEXT,
            cpu_percent REAL,
            memory_percent REAL,
            startup_latency REAL,
            response_time REAL,
            io_wait_time REAL,
            disk_read_rate REAL,
            disk_write_rate REAL,
            load_average REAL,
            network_bytes_sent BIGINT,
            network_bytes_recv BIGINT,
            context_switches BIGINT,
            system_temperature REAL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    cur.close()



# ─── Insert usage record ───
def insert_usage_record(conn, record):
    cur = conn.cursor()
    insert_sql = """
        INSERT INTO application_usage (
            username, process_name, pid, ppid, cmdline, terminal,
            status, cpu_percent, memory_percent, start_time, end_time,
            duration_secs, timestamp
        ) VALUES (
            %(username)s, %(process_name)s, %(pid)s, %(ppid)s, %(cmdline)s, %(terminal)s,
            %(status)s, %(cpu_percent)s, %(memory_percent)s, %(start_time)s, %(end_time)s,
            %(duration_secs)s, %(timestamp)s
        );
    """

    # Ensure missing fields are set to None
    for key in ["end_time", "duration_secs"]:
        record.setdefault(key, None)

    try:
        cur.execute(insert_sql, record)
        conn.commit()
    except Exception as e:
        LOG.error(f"Failed to insert record: {e}\nData: {record}")
        conn.rollback()
    finally:
        cur.close()


# def detect_anomalous_application_usage(record, state_cache={}):
def detect_anomalous_application_usage(record, state_cache=None):

    """
    Detects anomalous application usage based on:
    - Known sensitive applications
    - Unusual CPU/memory usage
    - Suspicious execution paths
    - Abnormal frequency of launches
    """
    if state_cache is None:
        state_cache = {}

    anomalies = []

    # 1. Sensitive apps (security tools, hacking tools, etc.)
    sensitive_apps = {"nmap", "hydra", "sqlmap", "john", "airmon-ng"}
    if record.get("process_name", "").lower() in sensitive_apps:
        anomalies.append(f"Sensitive application detected: {record['process_name']}")

    # 2. High CPU or memory usage (above threshold)
    cpu = record.get("cpu_percent", 0)
    mem = record.get("memory_percent", 0)
    if cpu > 40:
        anomalies.append(f"High CPU usage detected ({cpu}%) by {record['process_name']}")
    if mem > 40:
        anomalies.append(f"High memory usage detected ({mem}%) by {record['process_name']}")

    # 3. Suspicious paths (non-standard executable locations)
    cmdline = record.get("cmdline", "").lower()
    allowed_paths = ("/usr","/usr/bin", "/opt", "/snap", "/usr/local/bin")
    if cmdline and not cmdline.startswith(allowed_paths):
        anomalies.append(f"Suspicious execution path: {cmdline}")

    # 4. Odd-hour execution (midnight to 5AM)
    try:
        ts = record.get("timestamp")
        ts = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
        if ts and (ts.hour < 5 or ts.hour > 19):
            anomalies.append(f"Unusual execution time: {ts.hour}:00 for {record['process_name']}")
    except Exception:
        pass
    

    # 5. Frequency-based anomaly detection (too many launches in 1 minute)
    proc = record.get("process_name")
    now = datetime.now()
    history = state_cache.setdefault(proc, [])
    history.append(now)
    state_cache[proc] = [t for t in history if (now - t).seconds < 60]  # keep last 60s only
    if len(state_cache[proc]) > 5:
        anomalies.append(f"Frequent launches of {proc} detected ({len(state_cache[proc])}/min)")

    return anomalies if anomalies else None


def insert_latency_record(conn, record):
    cur = conn.cursor()
    insert_sql = """
        INSERT INTO latency_monitoring (
            username, 
            cpu_percent, 
            memory_percent, 
            startup_latency,
            response_time, 
            io_wait_time, 
            disk_read_rate,
            disk_write_rate,
            load_average,
            network_bytes_sent,
            network_bytes_recv,
            context_switches,
            system_temperature,
            timestamp
        ) VALUES (
            %(username)s, 
            %(cpu_percent)s, 
            %(memory_percent)s, 
            %(startup_latency)s,
            %(response_time)s, 
            %(io_wait_time)s, 
            %(disk_read_rate)s,
            %(disk_write_rate)s,
            %(load_average)s,
            %(network_bytes_sent)s,
            %(network_bytes_recv)s,
            %(context_switches)s,
            %(system_temperature)s,
            %(timestamp)s
        );
    """

    # Ensure optional fields are present
    for field in [
        "startup_latency", "response_time", "io_wait_time", 
        "disk_read_rate", "disk_write_rate", "load_average", 
        "network_bytes_sent", "network_bytes_recv", "context_switches", 
        "system_temperature"
    ]:
        record.setdefault(field, None)

    try:
        cur.execute(insert_sql, record)
        conn.commit()
    except Exception as e:
        LOG.error(f"Failed to insert latency record: {e}\nData: {record}")
        conn.rollback()
    finally:
        cur.close()


# def main():

def main(stop_event=None):
    conn = psycopg2.connect(**DB_CONFIG)
    ensure_table(conn)  # Ensure the application usage table exists
    create_latency_monitoring_table(conn)  # Ensure the latency monitoring table exists
    print("\033[1;92m!!!!!!!!! Application usage Consumer running (UDP) !!!!!!\033[0m")
    LOG.info("!!!!!!!!! Application usage Consumer running (UDP) !!!!!!")
    
    # AI startup self-check (load once and log)
    ai_status = _load_artifacts()
    if "error" in ai_status:
        LOG.error(f"[AI] Artifacts failed to load: {ai_status['error']}")
    else:
        LOG.info(
            "[AI] Artifacts loaded: features=%d | threshold=%.4f",
            len(ai_status.get("feature_cols", [])),
            ai_status.get("threshold", float("nan"))
        )


    # Helper: normalize datetimes before JSON
    def normalize_record(rec):
        return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in rec.items()}

    while not (stop_event and stop_event.is_set()):
        data, addr = sock.recvfrom(65535)
        metrics = json.loads(data.decode("utf-8"))

        # Only process system-metrics events
        if metrics.get("topic") != "system-metrics":
            continue

        usage_list = metrics.get("application_usage", [])

        # Insert application usage records
        if usage_list:
            for record in usage_list:
                print("[Application usage received]:", json.dumps(normalize_record(record), indent=2))
                LOG.info("[Application usage received]: %s", json.dumps(normalize_record(record), indent=2))

                # Convert timestamps if necessary
                for ts_field in ("start_time", "end_time", "timestamp"):
                    if isinstance(record.get(ts_field), str):
                        try:
                            record[ts_field] = datetime.fromisoformat(record[ts_field])
                        except Exception:
                            pass  # ignore invalid timestamp format

                # Insert into application_usage only on launch/exit
                event_type = record.get("event")
                if event_type in ("launch", "exit"):
                    insert_usage_record(conn, record)

                rule_reasons = detect_anomalous_application_usage(record) or []

                ai_out = predict_anomalous_application_usage(normalize_record(record))
                ai_reasons = []
                if ai_out.get("ai_error"):
                    LOG.error(f"[AI] Model inference error: {ai_out['ai_error']}")
                elif ai_out.get("ai_is_anomalous", 0) == 1:
                    ai_reasons.append(
                        f"AI flagged anomalous usage "
                        f"(composite={ai_out['ai_composite_score']:.3f}, "
                        f"iso={ai_out['ai_iso_score']:.3f}, "
                        f"ae={ai_out['ai_ae_recon_error']:.3f})"
                    )

                # Merge reasons and send exactly ONE anomaly if any
                combined_reasons = list(dict.fromkeys(rule_reasons + ai_reasons))  # de-dup, keep order
                if combined_reasons:
                    event_reason = " | ".join(combined_reasons)

                    ts = record.get("timestamp")
                    if isinstance(ts, datetime):
                        ts = ts.isoformat()
                    elif not ts:
                        ts = datetime.now().isoformat()

                    anomaly = {
                        "msg_id": "UEBA_SIEM_ANOMALOUS_APPLICATION_USAGE_MSG",
                        "event_type": "USER_ACTIVITY_EVENTS",
                        "event_name": "ANOMALOUS_APPLICATION_USAGE",
                        "event_reason": event_reason,
                        "timestamp": ts,
                        "log_text": json.dumps(normalize_record(record)),
                        "severity": "ALERT",
                        "username": record.get("username"),
                        "process_name": record.get("process_name"),
                        "pid": record.get("pid"),
                        "ppid": record.get("ppid"),
                        "cmdline": record.get("cmdline"),
                        "anomalous_application_name": record.get("process_name"),
                        "tty": record.get("terminal"),
                        "cpu_time": record.get("duration_secs"),
                        "ai_iso_score": ai_out.get("ai_iso_score"),
                        "ai_ae_recon_error": ai_out.get("ai_ae_recon_error"),
                        "ai_composite_score": ai_out.get("ai_composite_score"),
                        "ai_is_anomalous": ai_out.get("ai_is_anomalous"),
                    }

                    try:
                        store_anomaly_to_database_and_siem(anomaly)
                        siem_packet = build_anomalous_application_usage_packet(anomaly)
                        store_siem_ready_packet(asdict(siem_packet))
                    except Exception as e:
                        LOG.error(f"Error during database/siem operation: {e}")


        # Insert latency data from the same producer message
        latency_record = {
            "username":           metrics.get("username"),
            "cpu_percent":        metrics.get("cpu_usage"),
            "memory_percent":     metrics.get("memory_usage"),
            "startup_latency":    metrics.get("startup_latency"),
            "response_time":      metrics.get("response_time"),
            "io_wait_time":       metrics.get("io_wait_time"),
            "disk_read_rate":     metrics.get("disk_read_rate"),
            "disk_write_rate":    metrics.get("disk_write_rate"),
            "load_average":       metrics.get("avg_load"),
            "network_bytes_sent": metrics.get("network_bytes_sent"),
            "network_bytes_recv": metrics.get("network_bytes_recv"),
            "context_switches":   metrics.get("context_switches"),
            "system_temperature": metrics.get("system_temperature"),
            "timestamp":          metrics.get("timestamp") if metrics.get("timestamp") else datetime.now().isoformat()
        }

        insert_latency_record(conn, latency_record)




if __name__ == "__main__":
    main()
