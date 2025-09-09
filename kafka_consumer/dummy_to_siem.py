# -*- coding: utf-8 -*-
# Direct SIEM test sender (self-contained, no imports from other files)

import json
import uuid
import datetime
import logging
import requests
from fastapi import FastAPI
from pydantic import BaseModel, Field

# Hardcoded SIEM URL
SIEM_URL = "http://10.229.40.67:5000/api/soc/v0_90/siem/addProcessedLog"

# Fixed values
EVENT_TYPE = 6        # SECURITY_EVENTS
EVENT_SUB  = 38       # MALWARE_DETECTED
DEFAULT_SEV = 5       # CRITICAL

app = FastAPI(title="UEBA Ransomware SIEM Test API")

# --------------------------------------------------------------------
# SIEM connector function (local definition)
# --------------------------------------------------------------------
def send_json_packet(payload: dict) -> bool:
    try:
        safe_data = json.loads(json.dumps(payload, default=str))
        response = requests.post(SIEM_URL, json=safe_data)
        response.raise_for_status()
        logging.info("[SIEM] send OK")
        return True
    except requests.RequestException as e:
        logging.error(f"[SIEM] send failed: {e}")
        print(">>> SIEM send failed:", e)
        return False

# --------------------------------------------------------------------
# API model
# --------------------------------------------------------------------
class AttackInput(BaseModel):
    process_name: str
    indicator: str = Field(..., description="e.g., mass_encrypt")
    attacker_ip: str | None = None
    resource: str | None = None
    severity: int | None = None
    timestamp: str | None = None

# --------------------------------------------------------------------
# Build SIEM message
# --------------------------------------------------------------------
def _build_siem_message(sig: AttackInput) -> dict:
    ts = datetime.datetime.now()
    event_id = str(uuid.uuid4())
    sev = sig.severity or DEFAULT_SEV

    msg = {
        "eventId": event_id,
        "msgId": "5",
        "srcId": "7",
        "year": ts.year,
        "month": ts.month,
        "day": ts.day,
        "hour": ts.hour,
        "minute": ts.minute,
        "second": ts.second,
        "eventType": "9",
        "eventName": str(EVENT_SUB),
        "severity": str(sev),
        "eventReason": f"Ransomware detected",
        "attackerIp": sig.attacker_ip or "10.229.40.138",
        "attackerInfo": "Ransomware module",
        "deviceHostname": "test-host",
        "deviceUsername": "test-user",
        "serviceName": sig.process_name,
        "servicePath": sig.resource or "N/A",
        "deviceType": 2,
        "destinationIp": "N/A",
        "deviceMacId": "7c:8a:e1:98:95:b9",
        "deviceIp": "10.229.40.154",
        "logText": json.dumps({"notes": " RANSOMWARE ATTACK DETECTED"}),
        "url": SIEM_URL,
    }
    return {"MESSAGE": msg}

# --------------------------------------------------------------------
# Send function
# --------------------------------------------------------------------

def send_to_siem(sig: AttackInput | None = None):
    if sig:
        payload = _build_siem_message(sig)
    else:
        payload = _build_siem_message(
            AttackInput(process_name="dummy_proc", indicator="dummy")
        )

    print(">>> Sending SIEM payload:\n", json.dumps(payload, indent=2), flush=True)
    ok = send_json_packet(payload)
    if ok:
        print(">>> SIEM message sent OK")
    else:
        print(">>> SIEM message failed")

# --------------------------------------------------------------------
# FastAPI endpoint
# --------------------------------------------------------------------
@app.post("/ransomware/detection")
def ransomware_detection(sig: AttackInput):
    send_to_siem(sig)
    return {"ok": True}

# --------------------------------------------------------------------
# Main (dummy send once)
# --------------------------------------------------------------------
if __name__ == "__main__":
    send_to_siem()  # dummy fire at startup
