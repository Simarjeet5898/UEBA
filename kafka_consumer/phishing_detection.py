# -*- coding: utf-8 -*-
# Content-Type: application/json
# Required JSON fields: process_name (str), indicator (str)

import os
import json
import uuid
import logging
import requests
import psycopg2
from datetime import datetime
from fastapi import FastAPI
from pydantic import BaseModel, Field
# from kafka_consumer.helper import get_common_system_fields
from helper import get_common_system_fields

# ---- Load config ----
CONFIG_PATH = "/home/config.json"
with open(CONFIG_PATH, "r") as f:
    CONFIG = json.load(f)

# ---- DB config ----
DB_CONFIG = {
    "host": CONFIG["local_db"]["host"],
    "user": CONFIG["local_db"]["user"],
    "password": CONFIG["local_db"]["password"],
    "dbname": CONFIG["local_db"]["dbname"],
}

# ---- Fixed / mapped values ----
EVENT_TYPE  = CONFIG["event_type"]["UEBA_BEHAVIORAL_EVENTS"]   # e.g., 9
EVENT_SUB   = CONFIG["event_name"]["PHISHING_ATTEMPT"]         # e.g., 38
DEFAULT_SEV = CONFIG["mappings"]["severity"]["CRITICAL"]       # e.g., 5

# ---- SIEM endpoint (env > config > fallback) ----
SIEM_URL = (
    os.getenv("SIEM_API_URL")
    or CONFIG.get("siem_api_url")
    or "http://10.229.40.67:5000/api/soc/v0_90/siem/addProcessedLog"
)

app = FastAPI(title="UEBA Phising Detection API")

print(f"[LOAD] PHISHING_api from: {__file__}", flush=True)
print(f"[LOAD] SIEM_URL: {SIEM_URL}", flush=True)

# --------------------------------------------------------------------
# Models
# --------------------------------------------------------------------
class AttackInput(BaseModel):
    process_name: str
    indicator: str = Field(..., description="e.g., mass_encrypt")
    evidence: list[str] = []
    file_hash: str | None = None
    attacker_ip: str | None = None
    resource: str | None = None
    severity: int | None = None    # default -> CRITICAL
    risk_score: int | None = None  # default -> 95
    timestamp: str | None = None   # ISO; default -> now()

# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------
def _parse_ts(ts: str | None) -> datetime:
    if not ts:
        return datetime.now()
    try:
        return datetime.fromisoformat(ts.replace("Z", "").replace("z", ""))
    except Exception:
        return datetime.now()

def _ensure_table(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS anomalies_log (
                id SERIAL PRIMARY KEY,
                event_id VARCHAR(255),
                user_id VARCHAR(255),
                timestamp TIMESTAMP,
                event_type VARCHAR(255),
                event_subtype VARCHAR(255),
                severity VARCHAR(50),
                attacker_info TEXT,
                component VARCHAR(255),
                resource TEXT,
                event_reason TEXT,
                device_ip VARCHAR(50),
                device_mac VARCHAR(50),
                log_text TEXT,
                risk_score FLOAT
            );
        """)
    conn.commit()

def _siem_send(payload: dict) -> bool:
    """
    Sends the already-wrapped {"MESSAGE": {...}} payload to SIEM.
    Uses local requests as the source of truth and prints loudly.
    """
    safe = json.loads(json.dumps(payload, default=str))
    try:
        r = requests.post(SIEM_URL, json=safe)  # no timeout
        print(f"[SIEM] POST {SIEM_URL} -> {r.status_code}", flush=True)
        body_preview = r.text if len(r.text) <= 500 else r.text[:500] + "...(truncated)"
        print(f"[SIEM] RESP: {body_preview}", flush=True)
        r.raise_for_status()
        return True
    except Exception as e:
        logging.error(f"[SIEM] send failed: {e}")
        print(f">>> SIEM send failed: {e}", flush=True)
        return False

# --------------------------------------------------------------------
# Core insert + SIEM forward
# --------------------------------------------------------------------
def _insert_row(sig: AttackInput) -> str:
    sysf = get_common_system_fields()
    event_id = str(uuid.uuid4())
    ts = _parse_ts(sig.timestamp)
    sev = sig.severity or DEFAULT_SEV
    risk = sig.risk_score or 95

    # --- Metrics stored in DB log_text ---
    metrics = {
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "username": sysf.get("device_username", "unknown"),
        "ip_addresses": [sysf.get("device_ip_add", "0.0.0.0")],
        "mac_address": sysf.get("device_mac_id", "N/A"),
        "process_name": sig.process_name,
        "file_hash": sig.file_hash,
        "indicator": sig.indicator,
        "evidence": sig.evidence,
        "device_hostname": sysf.get("device_hostname", "unknown"),
        "notes": "Injected via Phising",
    }

    # --- Row for PostgreSQL ---
    row = (
        event_id,
        sysf.get("device_username", "unknown"),   # user_id
        ts,
        EVENT_TYPE,
        EVENT_SUB,
        sev,
        sig.attacker_ip or "N/A",
        "Phishing_detected",
        sig.resource or "N/A",
        f"Phishing detected: {sig.indicator}",
        sysf.get("device_ip_add", "0.0.0.0"),
        sysf.get("device_mac_id", "N/A"),
        json.dumps(metrics),
        risk
    )

    sql = """
        INSERT INTO anomalies_log (
            event_id, user_id, timestamp, event_type, event_subtype, severity,
            attacker_info, component, resource, event_reason,
            device_ip, device_mac, log_text, risk_score
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """

    # --- Insert into DB ---
    with psycopg2.connect(**DB_CONFIG) as conn:
        _ensure_table(conn)
        with conn.cursor() as cur:
            cur.execute(sql, row)
        conn.commit()

    print(">>> DB insert done", flush=True)

    # --- Prepare SIEM message ---
    siem_msg = {
        "MESSAGE": {
            "eventId": event_id,
            "msgId": "5",
            "srcId": "7",
            "year": ts.year,
            "month": ts.month,
            "day": ts.day,
            "hour": ts.hour,
            "minute": ts.minute,
            "second": ts.second,
            "eventType": str(EVENT_TYPE),
            "eventName": str(EVENT_SUB),
            "severity": str(sev),
            "eventReason": f"PHISHING_ATTEMPT_DETECTED: {sig.indicator}",
            "attackerIp": sig.attacker_ip or "N/A",
            "attackerInfo": "PHISHING",
            "deviceHostname": sysf.get("device_hostname", "unknown"),
            "deviceUsername": sysf.get("device_username", "unknown"),
            "serviceName": sig.process_name,
            "servicePath": sig.resource or "N/A",
            "deviceType": CONFIG["device_type"].get("PC", 2),
            "destinationIp": "N/A",
            "deviceMacId": sysf.get("device_mac_id", "N/A"),
            "deviceIp": sysf.get("device_ip_add", "0.0.0.0"),
            "logText": json.dumps(metrics),
            "url": SIEM_URL,
        }
    }

    # --- Forward to SIEM ---
    print(">>> Sending to SIEM...", flush=True)
    ok = _siem_send(siem_msg)
    if ok:
        print(">>> SIEM send OK", flush=True)
    else:
        print(">>> SIEM send FAILED", flush=True)

    return event_id

# --------------------------------------------------------------------
# Dummy direct SIEM test
# --------------------------------------------------------------------
def send_dummy_to_siem():
    import datetime
    event_id = str(uuid.uuid4())
    ts = datetime.datetime.now()

    dummy_msg = {
        "eventId": event_id,
        "msgId": "5",
        "srcId": "7",
        "year": ts.year,
        "month": ts.month,
        "day": ts.day,
        "hour": ts.hour,
        "minute": ts.minute,
        "second": ts.second,
        "eventType": str(EVENT_TYPE),
        "eventName": str(EVENT_SUB),
        "severity": str(DEFAULT_SEV),
        "eventReason": "Phising test event",
        "attackerIp": "127.0.0.1",
        "attackerInfo": "N/A",
        "deviceHostname": "host",
        "deviceUsername": "user",
        "serviceName": "process",
        "servicePath": "N/A",
        "deviceType": CONFIG["device_type"].get("PC", 2),
        "destinationIp": "N/A",
        "deviceMacId": "00:11:22:33:44:55",
        "deviceIp": "127.0.0.1",
        "logText": json.dumps({"notes": "UEBA TO SIEM SEND"}),
        "url": SIEM_URL,
    }

    print(">>> Sending message to SIEM...", flush=True)
    ok = _siem_send({"MESSAGE": dummy_msg})
    if ok:
        print(">>> Message sent OK", flush=True)
    else:
        print(">>> Message send failed", flush=True)

# --------------------------------------------------------------------
# API Routes
# --------------------------------------------------------------------

@app.post("/phishing/detection")
def phishing_detection(sig: AttackInput):
    anomaly_id = _insert_row(sig)
    return {"ok": True, "anomaly_id": anomaly_id}

# --------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------
def main(stop_event=None):
    import uvicorn, threading, time

    host = CONFIG["attack_api"]["host"]
    port = int(CONFIG["attack_api"]["port"])

    server = uvicorn.Server(
        uvicorn.Config(app, host=host, port=port, reload=False, log_config=None)
    )

    if stop_event is None:
        server.run()
    else:
        t = threading.Thread(target=server.run, daemon=True)
        t.start()
        while not stop_event.is_set():
            time.sleep(0.5)
        server.should_exit = True
        t.join(timeout=5)

if __name__ == "__main__":
    send_dummy_to_siem()
    # main()

# To test locally: open http://127.0.0.1:8081/docs
# in this in particular api fill the information and send.

# POST /phishing/detection
# http://10.229.10.40:8081/phishing/detection
# Content-Type: application/json

# {
#   "process_name": "outlook.exe",
#   "indicator": "phishing_link",
#   "evidence": ["clicked_link"],
#   "file_hash": null,
#   "attacker_ip": "45.33.12.7",
#   "resource": "http://malicious.example/path",
#   "severity": 4,
#   "risk_score": 80,
#   "timestamp": "2025-10-01T12:34:56Z"
# }

# {
#   "process_name": "outlook.exe",
#   "indicator": "phishing_link",
#   "evidence": ["clicked_link"],
#   "file_hash": null,
#   "attacker_ip": "45.33.12.7",
#   "resource": "http://malicious.example/path",
#   "severity": 4,
#   "risk_score": 80,
#   "timestamp": "2025-10-01T12:34:56Z"
# }
