from db_connector import get_db_connection
from datetime import datetime



# ---------- CREATE TABLE IF NOT EXISTS ----------
def init_data_exfiltration_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS data_exfiltration_config (
            id SERIAL PRIMARY KEY,
            sensitive_files TEXT[],
            sensitive_data_types TEXT[],
            sensitive_file_extensions TEXT[],
            trusted_ip_ranges TEXT[],
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()


# ---------- CREATE ----------
def add_data_exfiltration_config(sensitive_files, sensitive_data_types, sensitive_file_extensions, trusted_ip_ranges):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO data_exfiltration_config 
        (sensitive_files, sensitive_data_types, sensitive_file_extensions, trusted_ip_ranges, updated_at)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id;
    """, (sensitive_files, sensitive_data_types, sensitive_file_extensions, trusted_ip_ranges, datetime.now()))
    config_id = cursor.fetchone()[0]
    conn.commit()
    cursor.close()
    conn.close()
    return config_id


# ---------- READ (All) ----------
def get_all_data_exfiltration_configs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM data_exfiltration_config ORDER BY id;")
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result


# ---------- READ (Single) ----------
def get_data_exfiltration_config(config_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM data_exfiltration_config WHERE id = %s;", (config_id,))
    row = cursor.fetchone()
    columns = [desc[0] for desc in cursor.description]
    result = dict(zip(columns, row)) if row else None
    cursor.close()
    conn.close()
    return result


# ---------- UPDATE ----------
def update_data_exfiltration_config(config_id, sensitive_files, sensitive_data_types, sensitive_file_extensions, trusted_ip_ranges):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE data_exfiltration_config
        SET sensitive_files = %s,
            sensitive_data_types = %s,
            sensitive_file_extensions = %s,
            trusted_ip_ranges = %s,
            updated_at = %s
        WHERE id = %s;
    """, (sensitive_files, sensitive_data_types, sensitive_file_extensions, trusted_ip_ranges, datetime.now(), config_id))
    conn.commit()
    cursor.close()
    conn.close()
    return True


# ---------- DELETE ----------
def delete_data_exfiltration_config(config_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM data_exfiltration_config WHERE id = %s;", (config_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return True


# ---------- CREATE TABLE IF NOT EXISTS ----------
def init_privileged_user_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS privileged_user_config (
            id SERIAL PRIMARY KEY,
            privileged_users TEXT[],
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()


# ---------- CREATE ----------
def add_privileged_user_config(privileged_users):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO privileged_user_config 
        (privileged_users, updated_at)
        VALUES (%s, %s)
        RETURNING id;
    """, (privileged_users, datetime.now()))
    config_id = cursor.fetchone()[0]
    conn.commit()
    cursor.close()
    conn.close()
    return config_id


# ---------- READ (All) ----------
def get_all_privileged_user_configs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM privileged_user_config ORDER BY id;")
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result


# ---------- READ (Single) ----------
def get_privileged_user_config(config_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM privileged_user_config WHERE id = %s;", (config_id,))
    row = cursor.fetchone()
    columns = [desc[0] for desc in cursor.description]
    result = dict(zip(columns, row)) if row else None
    cursor.close()
    conn.close()
    return result


# ---------- UPDATE ----------
def update_privileged_user_config(config_id, privileged_users):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE privileged_user_config
        SET privileged_users = %s,
            updated_at = %s
        WHERE id = %s;
    """, (privileged_users, datetime.now(), config_id))
    conn.commit()
    cursor.close()
    conn.close()
    return True


# ---------- DELETE ----------
def delete_privileged_user_config(config_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM privileged_user_config WHERE id = %s;", (config_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return True


# ---------- CREATE TABLE IF NOT EXISTS ----------
def init_anomalous_file_access_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS anomalous_file_access_config (
            id SERIAL PRIMARY KEY,
            sensitive_files TEXT[],
            sensitive_file_extensions TEXT[],
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()


# ---------- CREATE ----------
def add_anomalous_file_access_config(sensitive_files, sensitive_file_extensions):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO anomalous_file_access_config 
        (sensitive_files, sensitive_file_extensions, updated_at)
        VALUES (%s, %s, %s)
        RETURNING id;
    """, (sensitive_files, sensitive_file_extensions, datetime.now()))
    config_id = cursor.fetchone()[0]
    conn.commit()
    cursor.close()
    conn.close()
    return config_id


# ---------- READ (All) ----------
def get_all_anomalous_file_access_configs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM anomalous_file_access_config ORDER BY id;")
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result


# ---------- READ (Single) ----------
def get_anomalous_file_access_config(config_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM anomalous_file_access_config WHERE id = %s;", (config_id,))
    row = cursor.fetchone()
    columns = [desc[0] for desc in cursor.description]
    result = dict(zip(columns, row)) if row else None
    cursor.close()
    conn.close()
    return result


# ---------- UPDATE ----------
def update_anomalous_file_access_config(config_id, sensitive_files, sensitive_file_extensions):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE anomalous_file_access_config
        SET sensitive_files = %s,
            sensitive_file_extensions = %s,
            updated_at = %s
        WHERE id = %s;
    """, (sensitive_files, sensitive_file_extensions, datetime.now(), config_id))
    conn.commit()
    cursor.close()
    conn.close()
    return True


# ---------- DELETE ----------
def delete_anomalous_file_access_config(config_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM anomalous_file_access_config WHERE id = %s;", (config_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return True

# ---------- CREATE TABLE IF NOT EXISTS ----------
def init_dormancy_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dormancy_config (
            id SERIAL PRIMARY KEY,
            dormancy_value INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()


# ---------- CREATE ----------
def add_dormancy_config(dormancy_value):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO dormancy_config 
        (dormancy_value, updated_at)
        VALUES (%s, %s)
        RETURNING id;
    """, (dormancy_value, datetime.now()))
    config_id = cursor.fetchone()[0]
    conn.commit()
    cursor.close()
    conn.close()
    return config_id


# ---------- READ (All) ----------
def get_all_dormancy_configs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM dormancy_config ORDER BY id;")
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result


# ---------- READ (Single) ----------
def get_dormancy_config(config_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM dormancy_config WHERE id = %s;", (config_id,))
    row = cursor.fetchone()
    columns = [desc[0] for desc in cursor.description]
    result = dict(zip(columns, row)) if row else None
    cursor.close()
    conn.close()
    return result


# ---------- UPDATE ----------
def update_dormancy_config(config_id, dormancy_value):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE dormancy_config
        SET dormancy_value = %s,
            updated_at = %s
        WHERE id = %s;
    """, (dormancy_value, datetime.now(), config_id))
    conn.commit()
    cursor.close()
    conn.close()
    return True


# ---------- DELETE ----------
def delete_dormancy_config(config_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM dormancy_config WHERE id = %s;", (config_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return True


# ---------- CREATE TABLE IF NOT EXISTS ----------
def init_bulk_data_operation_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS bulk_data_operation_config (
            id SERIAL PRIMARY KEY,
            threshold_value FLOAT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()


# ---------- CREATE ----------
def add_bulk_data_operation_config(threshold_value):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO bulk_data_operation_config 
        (threshold_value, updated_at)
        VALUES (%s, %s)
        RETURNING id;
    """, (threshold_value, datetime.now()))
    config_id = cursor.fetchone()[0]
    conn.commit()
    cursor.close()
    conn.close()
    return config_id


# ---------- READ (All) ----------
def get_all_bulk_data_operation_configs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM bulk_data_operation_config ORDER BY id;")
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result


# ---------- READ (Single) ----------
def get_bulk_data_operation_config(config_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM bulk_data_operation_config WHERE id = %s;", (config_id,))
    row = cursor.fetchone()
    columns = [desc[0] for desc in cursor.description]
    result = dict(zip(columns, row)) if row else None
    cursor.close()
    conn.close()
    return result


# ---------- UPDATE ----------
def update_bulk_data_operation_config(config_id, threshold_value):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE bulk_data_operation_config
        SET threshold_value = %s,
            updated_at = %s
        WHERE id = %s;
    """, (threshold_value, datetime.now(), config_id))
    conn.commit()
    cursor.close()
    conn.close()
    return True


# ---------- DELETE ----------
def delete_bulk_data_operation_config(config_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM bulk_data_operation_config WHERE id = %s;", (config_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return True


# ---------- CREATE TABLE IF NOT EXISTS ----------
def init_abnormal_login_logout_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS abnormal_login_logout_config (
            id SERIAL PRIMARY KEY,
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()


# ---------- CREATE ----------
def add_abnormal_login_logout_config(start_time, end_time):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO abnormal_login_logout_config 
        (start_time, end_time, updated_at)
        VALUES (%s, %s, %s)
        RETURNING id;
    """, (start_time, end_time, datetime.now()))
    config_id = cursor.fetchone()[0]
    conn.commit()
    cursor.close()
    conn.close()
    return config_id


# ---------- READ (All) ----------
def get_all_abnormal_login_logout_configs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM abnormal_login_logout_config ORDER BY id;")
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result


# ---------- READ (Single) ----------
def get_abnormal_login_logout_config(config_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM abnormal_login_logout_config WHERE id = %s;", (config_id,))
    row = cursor.fetchone()
    columns = [desc[0] for desc in cursor.description]
    result = dict(zip(columns, row)) if row else None
    cursor.close()
    conn.close()
    return result


# ---------- UPDATE ----------
def update_abnormal_login_logout_config(config_id, start_time, end_time):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE abnormal_login_logout_config
        SET start_time = %s,
            end_time = %s,
            updated_at = %s
        WHERE id = %s;
    """, (start_time, end_time, datetime.now(), config_id))
    conn.commit()
    cursor.close()
    conn.close()
    return True


# ---------- DELETE ----------
def delete_abnormal_login_logout_config(config_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM abnormal_login_logout_config WHERE id = %s;", (config_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return True


# ---------- CREATE TABLE IF NOT EXISTS ----------
def init_alert_suppression_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_suppression_config (
            id SERIAL PRIMARY KEY,
            usernames TEXT[],
            hostnames TEXT[],
            ip_ranges TEXT[],
            event_frequency_threshold INTEGER,
            event_sources TEXT[],
            timestamp_start TIMESTAMP,
            timestamp_end TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()


# ---------- CREATE ----------
def add_alert_suppression_config(usernames, hostnames, ip_ranges, event_frequency_threshold, event_sources, timestamp_start, timestamp_end):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alert_suppression_config 
        (usernames, hostnames, ip_ranges, event_frequency_threshold, event_sources, timestamp_start, timestamp_end, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id;
    """, (usernames, hostnames, ip_ranges, event_frequency_threshold, event_sources, timestamp_start, timestamp_end, datetime.now()))
    config_id = cursor.fetchone()[0]
    conn.commit()
    cursor.close()
    conn.close()
    return config_id


# ---------- READ (All) ----------
def get_all_alert_suppression_configs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alert_suppression_config ORDER BY id;")
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    result = [dict(zip(columns, row)) for row in rows]
    cursor.close()
    conn.close()
    return result


# ---------- READ (Single) ----------
def get_alert_suppression_config(config_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alert_suppression_config WHERE id = %s;", (config_id,))
    row = cursor.fetchone()
    columns = [desc[0] for desc in cursor.description]
    result = dict(zip(columns, row)) if row else None
    cursor.close()
    conn.close()
    return result


# ---------- UPDATE ----------
def update_alert_suppression_config(config_id, usernames, hostnames, ip_ranges, event_frequency_threshold, event_sources, timestamp_start, timestamp_end):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE alert_suppression_config
        SET usernames = %s,
            hostnames = %s,
            ip_ranges = %s,
            event_frequency_threshold = %s,
            event_sources = %s,
            timestamp_start = %s,
            timestamp_end = %s,
            updated_at = %s
        WHERE id = %s;
    """, (usernames, hostnames, ip_ranges, event_frequency_threshold, event_sources, timestamp_start, timestamp_end, datetime.now(), config_id))
    conn.commit()
    cursor.close()
    conn.close()
    return True


# ---------- DELETE ----------
def delete_alert_suppression_config(config_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alert_suppression_config WHERE id = %s;", (config_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return True
