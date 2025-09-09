#!/usr/bin/env python3
import os
import sys
import time
import signal
import threading
import importlib
# import traceback
import logging
from logging.handlers import TimedRotatingFileHandler

# ---------- STATIC PATHS ----------
# ROOT = "/home/simar/Documents/UEBA/UEBA_BACKEND"
ROOT = "/home/simar/Documents/UEBA/UEBA_BACKEND"

KC   = f"{ROOT}/kafka_consumer"

for p in (ROOT, KC):
    if p not in sys.path:
        sys.path.insert(0, p)

os.environ.setdefault("UEBA_CONFIG", "/home/config.json")

# ---------- LOGGING SETUP ----------

from pathlib import Path
from datetime import datetime

USER_HOME = Path.home()
BASE_LOG_DIR = USER_HOME / "ueba_server_log"

# Create date-based folder like ueba_server_26Aug
today_str = datetime.now().strftime("ueba_server_%d%b")
DAILY_LOG_DIR = BASE_LOG_DIR / today_str
CONSUMER_LOG_DIR = DAILY_LOG_DIR / "consumers"

# Ensure dirs exist
os.makedirs(CONSUMER_LOG_DIR, exist_ok=True)

def make_logger(name, log_path):
    """Create a logger with daily rotating logs (keeps 7 days)."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    handler = TimedRotatingFileHandler(
        log_path, when="midnight", interval=1, backupCount=7, encoding="utf-8"
    )
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(handler)
    return logger

# master logger for bootstrap/shutdown → inside DAILY_LOG_DIR
master_log = make_logger("consumer_main", DAILY_LOG_DIR / "server.log")

stop_event = threading.Event()

def _run_main(module_name: str, friendly: str, logfile: str):
    """Imports module by name and runs module.main() in this thread."""
    logger = make_logger(friendly, logfile)
    try:
        mod = importlib.import_module(module_name)
        if not hasattr(mod, "main"):
            logger.error(f"[FATAL] {friendly} ({module_name}) has no main()")
            return
        logger.info(f"[START] {friendly}")
        mod.main(stop_event=stop_event)
        logger.info(f"[EXIT]  {friendly} main() returned")
    except Exception:
        logger.exception(f"[CRASH] {friendly}")

def _spawn(module_name: str, friendly: str, delay_s: float = 0.0, is_dashboard=False) -> threading.Thread:
    def target():
        if delay_s:
            time.sleep(delay_s)

        if is_dashboard:
            log_path = DAILY_LOG_DIR / "ueba_dashboard_api.log"
        else:
            log_path = CONSUMER_LOG_DIR / f"{friendly.replace(' ', '_').lower()}.log"

        _run_main(module_name, friendly, str(log_path))

    t = threading.Thread(target=target, name=friendly, daemon=True)
    t.start()
    return t


# ---------- BOOT ----------
def main():
    master_log.info("==== UEBA Server bootstrap starting ====")
    master_log.info(f"UEBA_CONFIG -> {os.environ.get('UEBA_CONFIG')}")

    threads = []

    threads.append(_spawn("kafka_consumer.udp_dispatcher", "UDP Dispatcher"))
    threads.append(_spawn("kafka_consumer.application_usage_consumer_udp", "Application Usage Consumer", delay_s=0.5))
    threads.append(_spawn("kafka_consumer.authentication_monitoring_consumer_udp", "Authentication Monitoring Consumer", delay_s=0.6))
    threads.append(_spawn("kafka_consumer.process_monitoring_consumer_udp", "Process Monitoring Consumer", delay_s=0.7))
    threads.append(_spawn("kafka_consumer.SRU_consumer_udp", "SRU Consumer", delay_s=0.8))
    threads.append(_spawn("kafka_consumer.login_events_consumer_udp", "Login Events Consumer", delay_s=0.2))
    threads.append(_spawn("kafka_consumer.connected_entities_consumer_udp", "Connected Entities Consumer", delay_s=0.3))
    threads.append(_spawn("kafka_consumer.file_sys_monitoring_consumer_udp", "File System Monitoring Consumer", delay_s=0.4))


    # Dashboard API → separate log file outside "consumers"
    threads.append(_spawn("api_server", "UEBA Dashboard API", delay_s=1.2, is_dashboard=True))

    def handle_signal(sig, frame):
        master_log.info(f"[SHUTDOWN] Signal {sig} received. Stopping…")
        stop_event.set()

    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(s, handle_signal)

    master_log.info("==== UEBA Server bootstrap complete. Running. ====")
    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    finally:
        master_log.info("[EXIT] Main loop done.")
        stop_event.set()
        time.sleep(1)
        os._exit(0)

if __name__ == "__main__":
    main()

