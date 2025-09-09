# db_connector.py
import os
import json
import psycopg2

CONFIG_PATH = os.environ.get("UEBA_CONFIG", "/home/config.json")
with open(CONFIG_PATH, "r") as f:
    _cfg = json.load(f)

# Build db_config dynamically, skip blanks
_local = _cfg.get("local_db", {})
db_config = {}
for key in ["host", "user", "password", "dbname"]:
    val = _local.get(key)
    if val:  # only include if non-empty / non-null
        db_config[key] = val

def get_db_connection():
    """Establish a connection to the PostgreSQL database."""
    return psycopg2.connect(**db_config)

def ensure_table_exists():
    """Ensure anomalies_log table exists (schema aligned with writers)."""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
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
                resource VARCHAR(255),
                event_reason TEXT,
                device_ip VARCHAR(50),
                device_mac VARCHAR(50),
                log_text TEXT,
                risk_score FLOAT
            );
        """)
        conn.commit()
        return True
    except Exception as e:
        print(f"[db_connector] ensure_table_exists error: {e}")
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()

ensure_table_exists()
