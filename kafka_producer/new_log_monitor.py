import subprocess
import re
import psutil
import pytz
from datetime import datetime, timedelta, timezone
import os
import time
from watchdog.observers import Observer
from typing import List, Dict
import logging
from watchdog.events import FileSystemEventHandler
import threading
import socket
import ipaddress
import platform
import shutil
import pwd
import signal
import json
from datetime import datetime, timezone, timedelta


_last_login_check = datetime.now(timezone.utc)
_last_failed_check = datetime.now(timezone.utc)


if platform.system() == "Windows":
    import wmi
    import ctypes
    import win32gui
    import win32evtlog
    import win32process
    import string
    import xml.etree.ElementTree as ET
    import winreg
    import win32file
    import pythoncom


def get_lan_and_internet_ips():
    lan_ip = None
    internet_ip = None

    # 1. Find LAN IP (private, non-loopback)
    for iface_addrs in psutil.net_if_addrs().values():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
                if not ip.startswith("127.") and ipaddress.ip_address(ip).is_private:
                    lan_ip = ip
                    break
        if lan_ip:
            break

    # 2. Find Internet IP (via socket routing)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        internet_ip = s.getsockname()[0]
        s.close()
    except Exception:
        internet_ip = "Unknown"

    return lan_ip or "Unknown", internet_ip or "Unknown"



def get_gpu_usage():
    # Only proceed if nvidia-smi exists (works on both Linux and Windows with NVIDIA driver)
    if not shutil.which("nvidia-smi"):
        return 0  # Gracefully return 0 if nvidia-smi not available

    try:
        result = subprocess.run(["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"],
                                capture_output=True, text=True)
        output = result.stdout.strip()

        if not output.isdigit():
            print("GPU Usage Fetch Error:", output)
            return 0
        
        return int(output)
    except Exception as e:
        print("GPU Usage Exception:", e)
        return 0


def get_io_wait_time():
    try:
        return psutil.cpu_times().iowait
    except AttributeError:
        return None

def get_context_switches():
    try:
        return psutil.cpu_stats().ctx_switches
    except Exception:
        return None

def get_system_temperature():
    try:
        output = subprocess.check_output("sensors", shell=True).decode()
        for line in output.split("\n"):
            if "Package id 0" in line or "Core 0" in line:
                return float(line.split("+")[1].split("°C")[0].strip())
    except:
        return None 
    

def get_startup_latency():
    try:
        # Get the system's boot time
        boot_time = psutil.boot_time()
        
        # Get the current time
        current_time = time.time()
        
        # Calculate startup latency (time since boot)
        startup_latency = current_time - boot_time
        
        return startup_latency  # Returns the startup latency in seconds
    except Exception as e:
        return None  # If something goes wrong, return None


def get_num_open_windows():
    try:
        if platform.system() == "Windows":

            def is_real_window(hWnd):
                if not win32gui.IsWindowVisible(hWnd):
                    return False
                if win32gui.GetWindowText(hWnd) == "":
                    return False
                return True

            windows = []
            win32gui.EnumWindows(lambda hWnd, param: windows.append(hWnd) if is_real_window(hWnd) else None, None)
            return len(windows)

        else:
            result = subprocess.run(["wmctrl", "-l"], capture_output=True, text=True)
            return len(result.stdout.splitlines())
    except Exception as e:
        print("Open Windows Count Error:", e)
        return 0




# # Start with an old time so only new failures are counted after first run
# last_checked_time = datetime.now(timezone.utc)

# def get_failed_logins(
#     log_file: str = "/var/log/auth.log",
#     tail_lines: int = 200
# ) -> int:
#     """
#     Reads the auth.log to count failed login attempts since the last function call.
#     Uses tail to efficiently read only the most recent lines.
#     Returns: total number of failed login attempts
#     """
#     global last_checked_time

#     now_utc = datetime.now(timezone.utc)
#     local_tz = datetime.now().astimezone().tzinfo
#     current_time = now_utc

#     # Regex patterns for timestamps
#     iso_re = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})")
#     syslog_re = re.compile(r"(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")

#     # Patterns for authentication failures
#     auth_failure_patterns = [
#         re.compile(r"pam_unix\(.*:auth\):\s+authentication failure"),
#         re.compile(r"sudo:.* authentication failure"),
#         re.compile(r"sshd\[\d+\]: Failed password for"),
#         re.compile(r"Failed password for .* from .* port \d+ ssh2"),
#     ]

#     try:
#         out = subprocess.check_output(
#             ["tail", "-n", str(tail_lines), log_file],
#             text=True,
#             stderr=subprocess.DEVNULL,
#             timeout=1
#         )
#     except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
#         print("Could not read log file")
#         return 0

#     failed_attempts = 0
#     max_ts = last_checked_time

#     for line in out.splitlines():
#         ts = None

#         # Try ISO timestamp first
#         m1 = iso_re.search(line)
#         if m1:
#             try:
#                 ts = datetime.fromisoformat(m1.group(1)).astimezone(timezone.utc)
#             except ValueError:
#                 print("Failed to parse ISO timestamp in line:", line)
#                 continue
#         # Fallback to syslog
#         else:
#             m2 = syslog_re.match(line)
#             if m2:
#                 mon, day, timestr = m2.groups()
#                 year = now_utc.year
#                 try:
#                     dt_naive = datetime.strptime(
#                         f"{year} {mon} {int(day):02d} {timestr}",
#                         "%Y %b %d %H:%M:%S"
#                     )
#                     ts = dt_naive.replace(tzinfo=local_tz).astimezone(timezone.utc)
#                 except ValueError:
#                     # print("Failed to parse syslog timestamp in line:", line)
#                     continue

#         # print("Line TS:", ts, "| last_checked_time:", last_checked_time, "| current_time:", current_time)
#         # if ts and last_checked_time < ts <= current_time: #Added on 15 sept by simar
#         if ts and ts > last_checked_time and ts <= current_time:
#             for pattern in auth_failure_patterns:
#                 if pattern.search(line):
#                     # print("[MATCH]", pattern.pattern, "=>", line)
#                     failed_attempts += 1
#                     if ts > max_ts:
#                         max_ts = ts
#                     break  # Prevent double counting

#     # Always update the last_checked_time to the latest we saw
#     if max_ts > last_checked_time:
#         last_checked_time = max_ts
#     else:
#         last_checked_time = current_time

#     # print("Returning", failed_attempts, "failed login attempts")
#     return failed_attempts

# Start with None so we can cleanly baseline on first call
last_checked_time = None

def get_failed_logins(
    log_file: str = "/var/log/auth.log",
    tail_lines: int = 200
) -> int:
    """
    Count only *new* failed login attempts since last call.
    Returns the number of new failures detected.
    """
    global last_checked_time

    now_utc = datetime.now(timezone.utc)
    local_tz = datetime.now().astimezone().tzinfo
    current_time = now_utc

    # First ever call → just baseline, return 0 (no backcounting)
    if last_checked_time is None:
        last_checked_time = current_time
        return 0

    # Regex for syslog timestamps
    iso_re    = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})")
    syslog_re = re.compile(r"(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")

    # Canonical SSHD failed login line
    ssh_fail_re = re.compile(
        r"sshd\[\d+\]:\s*Failed password for (?:invalid user )?\S+ from [0-9A-Fa-f\.:]+"
    )

    try:
        out = subprocess.check_output(
            ["tail", "-n", str(tail_lines), log_file],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=1
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return 0

    failed_attempts = 0
    max_ts = last_checked_time

    for line in out.splitlines():
        ts = None

        # Try ISO timestamp first
        m1 = iso_re.search(line)
        if m1:
            try:
                ts = datetime.fromisoformat(m1.group(1)).astimezone(timezone.utc)
            except ValueError:
                continue
        else:
            m2 = syslog_re.match(line)
            if m2:
                mon, day, timestr = m2.groups()
                year = now_utc.year
                try:
                    dt_naive = datetime.strptime(
                        f"{year} {mon} {int(day):02d} {timestr}",
                        "%Y %b %d %H:%M:%S"
                    )
                    ts = dt_naive.replace(tzinfo=local_tz).astimezone(timezone.utc)
                except ValueError:
                    continue

        # Count only new failures since last_checked_time
        if ts and last_checked_time < ts <= current_time:
            if ssh_fail_re.search(line):
                failed_attempts += 1
                if ts > max_ts:
                    max_ts = ts

    # Advance the watermark
    last_checked_time = max_ts if max_ts > last_checked_time else current_time
    return failed_attempts



def get_num_gui_processes():
    result = subprocess.run(["ps", "-e", "-o", "comm"], capture_output=True, text=True)
    gui_processes = [line for line in result.stdout.splitlines() if "Xorg" in line or "gnome" in line or "kde" in line]
    return len(gui_processes)


def get_cpu_usage():
    # First call to initialize the measurement
    psutil.cpu_percent(interval=None)
    # Actual usage over 1 second
    return psutil.cpu_percent(interval=1)


def get_avg_load():
    try:
        if platform.system() == "Windows":
            # No loadavg on Windows, so we return CPU usage over 1 second
            return round(psutil.cpu_percent(interval=1), 2)
        else:
            load_avg = psutil.getloadavg()[0]
            return round(load_avg * 100, 2)
    except Exception as e:
        print("Load Average Fetch Error:", e)
        return 0.0


def get_open_files():
    open_files_count = 0
    for proc in psutil.process_iter(['pid', 'open_files']):
        try:
            # Get list of open files for this process
            open_files = proc.info.get('open_files', [])
            if open_files:
                open_files_count += len(open_files)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return open_files_count

# def get_total_files():
#   total_files = 0
#   for root, _, files in os.walk("/"):  # Scans entire system
#       total_files += len(files)
#   return total_files

def get_total_files():
    total_files = 0
    try:
        if platform.system() == "Windows":
            import string
            drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
            for drive in drives:
                for root, _, files in os.walk(drive):
                    total_files += len(files)
        else:
            for root, _, files in os.walk("/"):
                total_files += len(files)
    except Exception as e:
        print("Total File Count Error:", e)
        return 0
    return total_files

if platform.system() == "Windows":
    AUTH_LOG = "Security"  # Event Log name in Windows

    # Match successful login (Event ID 4624) messages from Windows logs (you will parse Event Log entries)
    ISO_RE = re.compile(r".*Security ID:\s+S-1-5-.*Logon Type:\s+\d+.*")  # loose match; you’ll refine it based on actual event text
    SYSLOG_RE = ISO_RE  # Same in Windows — not actually used with syslog format
else:
    AUTH_LOG = "/var/log/auth.log"
    ISO_RE = re.compile(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+\-]\d{2}:\d{2}).*gdm-password\]: gkr-pam: unlocked login keyring"
    )
    SYSLOG_RE = re.compile(
        r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2}).*gdm-password\]: gkr-pam: unlocked login keyring"
    )


from datetime import datetime
import tzlocal  # pip install tzlocal

_seen_logins = set()
_initialized = False

def get_successful_logins():
    global _seen_logins, _initialized
    new_events = []

    try:
        output = subprocess.check_output(['who'], text=True)

        for line in output.strip().split('\n'):
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) >= 5 and parts[-1].startswith("(") and parts[-1].endswith(")"):
                user = parts[0]
                terminal = parts[1]
                login_time = ' '.join(parts[2:4])   # e.g. "Sep 12 13:20"
                source_ip = parts[4][1:-1]

                login_key = f"{user}|{terminal}|{source_ip}|{login_time}"
                if login_key in _seen_logins:
                    continue
                _seen_logins.add(login_key)

                if not _initialized:
                    continue

                local_tz = tzlocal.get_localzone()
                try:
                    full_time_str = f"{login_time} {datetime.now().year}"
                    # who prints: "Sep 12 13:20"
                    log_dt = datetime.strptime(full_time_str, "%b %d %H:%M %Y")
                    log_dt = log_dt.replace(tzinfo=local_tz)
                except Exception:
                    # fallback: use *now* in local time
                    log_dt = datetime.now(local_tz)

                event = {
                    "timestamp": log_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "username": user,
                    "source_ip": source_ip,
                    "source_hostname": None,
                    "method": "SSH"
                }
                new_events.append(event)

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] subprocess failed: {e}")

    if not _initialized:
        _initialized = True

    return new_events


# import subprocess
# from datetime import datetime, timezone

# _seen_logins = set()
# _initialized = False

# def get_successful_logins():
#     global _seen_logins, _initialized
#     new_events = []

#     # ---------- SSH / Local via "who" ----------
#     try:
#         output = subprocess.check_output(['who'], text=True)

#         for line in output.strip().split('\n'):
#             if not line.strip():
#                 continue

#             parts = line.split()
#             if len(parts) >= 5 and parts[-1].startswith("(") and parts[-1].endswith(")"):
#                 user = parts[0]
#                 terminal = parts[1]
#                 login_time = ' '.join(parts[2:4])
#                 source_ip = parts[4][1:-1]  # strip parentheses

#                 login_key = f"ssh|{user}|{terminal}|{source_ip}|{login_time}"
#                 if login_key in _seen_logins:
#                     continue
#                 _seen_logins.add(login_key)

#                 if not _initialized:
#                     continue

#                 try:
#                     full_time_str = f"{login_time} {datetime.now().year}"
#                     log_dt = datetime.strptime(full_time_str, "%Y-%m-%d %H:%M:%S %Y").astimezone(timezone.utc)
#                 except Exception:
#                     log_dt = datetime.now(timezone.utc)

#                 event = {
#                     "timestamp": log_dt.strftime("%Y-%m-%d %H:%M:%S"),
#                     "username": user,
#                     "source_ip": source_ip,
#                     "source_hostname": None,
#                     "method": "SSH"
#                 }
#                 new_events.append(event)

#     except subprocess.CalledProcessError as e:
#         print(f"[ERROR] subprocess failed: {e}")

#     # ---------- su / sudo via auth.log ----------
#     try:
#         with open("/var/log/auth.log", "r") as f:
#             lines = f.readlines()[-200:]  # check only recent lines

#         for line in lines:
#             ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

#             if "session opened for user" in line and "su:" in line:
#                 # Example: pam_unix(su:session): session opened for user root by simar(uid=1000)
#                 parts = line.split()
#                 target_user = parts[parts.index("user") + 1] if "user" in parts else "unknown"
#                 actor = parts[parts.index("by") + 1] if "by" in parts else "unknown"
#                 login_key = f"su|{actor}|{target_user}"
#                 if login_key in _seen_logins:
#                     continue
#                 _seen_logins.add(login_key)

#                 event = {
#                     "timestamp": ts,
#                     "username": target_user,
#                     "source_ip": "localhost",
#                     "source_hostname": None,
#                     "method": "SU",
#                     "extra": {"actor": actor}
#                 }
#                 new_events.append(event)

#             elif "COMMAND=" in line and "sudo:" in line and "TTY=" in line:
#                 # Example: sudo: simar : TTY=pts/1 ; PWD=/home/simar ; USER=root ; COMMAND=/bin/bash
#                 parts = line.split()
#                 actor = parts[1] if len(parts) > 1 else "unknown"
#                 target_user = "root"
#                 login_key = f"sudo|{actor}|{target_user}|{line}"
#                 if login_key in _seen_logins:
#                     continue
#                 _seen_logins.add(login_key)

#                 event = {
#                     "timestamp": ts,
#                     "username": target_user,
#                     "source_ip": "localhost",
#                     "source_hostname": None,
#                     "method": "SUDO",
#                     "extra": {"actor": actor, "raw": line.strip()}
#                 }
#                 new_events.append(event)

#     except FileNotFoundError:
#         pass  # auth.log not available

#     if not _initialized:
#         _initialized = True

#     return new_events






def check_recent_unlock(tail_lines: int = 100, window_secs: int = 10):
    """
    Returns the timestamp of a recent unlock/login event within the last `window_secs` seconds, or None.
    Works on both Linux (auth.log) and Windows (Security event log).
    """
    now = datetime.now().astimezone()
    window_start = now - timedelta(seconds=window_secs)
    local_tz = now.tzinfo

    # print(f"[DEBUG] Now: {now}, tzinfo: {now.tzinfo}")
    # print(f"[DEBUG] Window start: {window_start}, tzinfo: {window_start.tzinfo}")

    if platform.system() == "Windows":
        try:
            server = 'localhost'
            log_type = 'Security'
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            hand = win32evtlog.OpenEventLog(server, log_type)

            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break

                for ev in events:
                    if ev.EventID == 4624:  # Successful login
                        ts = ev.TimeGenerated
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        ts = ts.astimezone(local_tz)

                        # print(f"[DEBUG] Successful login ts: {ts}, tzinfo: {ts.tzinfo}")

                        if window_start <= ts <= now:
                            # print(f"[DEBUG] Match found: {ts}")
                            win32evtlog.CloseEventLog(hand)
                            return ts.strftime("%Y-%m-%d %H:%M:%S")

                    ev_ts = ev.TimeGenerated
                    if ev_ts.tzinfo is None:
                        ev_ts = ev_ts.replace(tzinfo=timezone.utc)
                    ev_ts = ev_ts.astimezone(local_tz)

                    # print(f"[DEBUG] Checking ev.TimeGenerated: {ev_ts}, tzinfo: {ev_ts.tzinfo}")

                    if ev_ts < window_start:
                        # print(f"[DEBUG] Old event, exiting: {ev_ts}")
                        win32evtlog.CloseEventLog(hand)
                        return None

            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            # print(f"[UnlockCheck][Windows] Error: {e}")
            return None

    else:
        try:
            output = subprocess.check_output(
                ["tail", "-n", str(tail_lines), AUTH_LOG],
                text=True,
                timeout=1
            )
            lines = output.strip().splitlines()
        except Exception as e:
            return None

        for line in reversed(lines):
            if "gkr-pam: unlocked login keyring" not in line:
                continue

            ts = None

            # match full ISO timestamp (without +05:30 timezone for simplicity)
            match = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
            if match:
                try:
                    ts = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=local_tz)
                except Exception:
                    continue

            if ts and window_start <= ts <= now:
                return ts.strftime("%Y-%m-%d %H:%M:%S")

        return None




# from collections import Counter

# _iso_re = re.compile(
#     r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[\+\-]\d{2}:\d{2})"
# )
# _syslog_re = re.compile(
#     r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Failed password"
# )
# _ip_re = re.compile(
#     r"from\s+(\d{1,3}(?:\.\d{1,3}){3})"
# )


from collections import Counter

if platform.system() == "Windows":
    def get_failed_login_ips_windows(window_secs: int = 300) -> Counter:
        import win32evtlog

        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=window_secs)
        ip_counter = Counter()

        try:
            server = 'localhost'
            log_type = 'Security'
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            hand = win32evtlog.OpenEventLog(server, log_type)

            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break

                for ev in events:
                    if ev.EventID == 4625:  # Failed login
                        ts = ev.TimeGenerated.replace(tzinfo=timezone.utc)
                        if ts < window_start:
                            win32evtlog.CloseEventLog(hand)
                            return ip_counter

                        inserts = ev.StringInserts
                        if inserts and len(inserts) >= 19:
                            ip = inserts[18]
                            if ip and ip != '-' and re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                                ip_counter[ip] += 1

            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            print("[Windows][Failed Login] Error:", e)

        return ip_counter

else:
    _iso_re = re.compile(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[\+\-]\d{2}:\d{2})"
    )
    _syslog_re = re.compile(
        r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Failed password"
    )
    _ip_re = re.compile(
        r"from\s+(\d{1,3}(?:\.\d{1,3}){3})"
    )

    def get_failed_login_ips_linux(log_file="/var/log/auth.log", window_secs=300, tail_lines=500) -> Counter:
        now = datetime.now().astimezone()
        window_start = now - timedelta(seconds=window_secs)
        local_tz = now.tzinfo
        ip_counter = Counter()

        try:
            output = subprocess.check_output(["tail", "-n", str(tail_lines), log_file], text=True, timeout=1)
            lines = output.strip().splitlines()
        except Exception as e:
            print("[Linux][Failed Login] Error reading log:", e)
            return ip_counter

        for line in reversed(lines):
            ts = None

            m1 = _iso_re.search(line)
            if m1:
                try:
                    ts = datetime.fromisoformat(m1.group(1)).astimezone(local_tz)
                except ValueError:
                    continue
            else:
                m2 = _syslog_re.search(line)
                if m2:
                    try:
                        mon, day, timestr = m2.groups()
                        dt_naive = datetime.strptime(f"{now.year} {mon} {day} {timestr}", "%Y %b %d %H:%M:%S")
                        ts = dt_naive.replace(tzinfo=local_tz)
                    except ValueError:
                        continue

            if ts and window_start <= ts <= now:
                ip_match = _ip_re.search(line)
                if ip_match:
                    ip_counter[ip_match.group(1)] += 1

        return ip_counter



def get_failed_ssh_attempts(
    log_file: str = "/var/log/auth.log",
    tail_lines: int = 200,
    window_sec: int = 5
) -> tuple[int, Counter]:
    now_utc = datetime.now(timezone.utc)
    threshold = now_utc - timedelta(seconds=window_sec)
    local_tz = datetime.now().astimezone().tzinfo
    total = 0
    ip_counts = Counter()

    if platform.system() == "Windows":
        try:
            server = 'localhost'
            log_type = 'Security'
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            hand = win32evtlog.OpenEventLog(server, log_type)

            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break

                for ev in events:
                    if ev.EventID != 4625:
                        continue

                    ts = ev.TimeGenerated.replace(tzinfo=timezone.utc)
                    if ts < threshold:
                        win32evtlog.CloseEventLog(hand)
                        return total, ip_counts

                    inserts = ev.StringInserts
                    if inserts and len(inserts) >= 19:
                        ip = inserts[18]
                        if ip and ip != '-' and re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                            ip_counts[ip] += 1
                            total += 1

            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            print("[Windows][Failed SSH] Error:", e)
            return 0, Counter()

    else:
        try:
            out = subprocess.check_output(
                ["tail", "-n", str(tail_lines), log_file],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=1
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            return 0, Counter()

        for line in out.splitlines():
            if "sshd" not in line or "Failed password" not in line:
                continue

            ts = None
            m1 = _iso_re.search(line)
            if m1:
                try:
                    ts = datetime.fromisoformat(m1.group(1))
                except ValueError:
                    continue
            else:
                m2 = _syslog_re.match(line)
                if m2:
                    mon, day, timestr = m2.groups()
                    year = now_utc.year
                    try:
                        dt_naive = datetime.strptime(
                            f"{year} {mon} {int(day):02d} {timestr}",
                            "%Y %b %d %H:%M:%S"
                        )
                        ts = dt_naive.replace(tzinfo=local_tz).astimezone(timezone.utc)
                    except ValueError:
                        continue

            if ts and ts >= threshold:
                m_ip = _ip_re.search(line)
                if m_ip:
                    ip = m_ip.group(1)
                    ip_counts[ip] += 1
                    total += 1
                else:
                    print(f"Warning: Failed to extract IP from log entry: {line}")

    return total, ip_counts


def get_recent_remote_logins() -> dict[str, str]:
    """
    Returns a dictionary mapping usernames to their most recent remote IPs
    from successful SSH (Linux) or remote logon (Windows) events that occurred
    *since the last call*.
    """
    global _last_login_check
    now_utc = datetime.now(timezone.utc)
    user_ip_map = {}

    if platform.system() == "Windows":
        # Implement Windows event log logic here if needed
        _last_login_check = now_utc
        return user_ip_map

    # Linux path
    log_file = "/var/log/auth.log"
    if not os.path.exists(log_file):
        return user_ip_map

    iso_re = re.compile(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[\+\-]\d{2}:\d{2}).*sshd\[\d+\]: Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)"
    )
    sys_re = re.compile(
        r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)"
    )

    try:
        lines = subprocess.check_output(
            ["tail", "-n", "200", log_file],
            text=True, stderr=subprocess.DEVNULL
        ).splitlines()
    except subprocess.CalledProcessError:
        return user_ip_map

    local_tz = datetime.now().astimezone().tzinfo

    for line in lines:
        username = None
        ip = None
        log_ts = None

        m = iso_re.search(line)
        if m:
            ts_str, username, ip = m.groups()
            try:
                log_ts = datetime.fromisoformat(ts_str).astimezone(timezone.utc)
            except ValueError:
                continue
        else:
            m2 = sys_re.match(line)
            if m2:
                mon, day, timestr, username, ip = m2.groups()
                year = now_utc.year
                try:
                    dt_naive = datetime.strptime(f"{year} {mon} {int(day):02d} {timestr}",
                                                 "%Y %b %d %H:%M:%S")
                    log_ts = dt_naive.replace(tzinfo=local_tz).astimezone(timezone.utc)
                except ValueError:
                    continue

        if log_ts and username and ip and log_ts > _last_login_check:
            user_ip_map[username] = ip

    _last_login_check = now_utc
    return user_ip_map


def count_cron_jobs():
    """Returns the number of scheduled jobs (crontab on Linux, Task Scheduler on Windows)."""
    if platform.system() == "Windows":
        try:
            result = subprocess.run(["schtasks", "/Query", "/FO", "LIST", "/V"],
                                    capture_output=True, text=True, check=True)
            output = result.stdout
            # Count each task entry by counting how many times "TaskName:" appears
            return output.count("TaskName:")
        except subprocess.CalledProcessError:
            return 0
    else:
        try:
            result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, check=True)
            crontab_content = result.stdout.strip()
            if not crontab_content:
                return 0
            return sum(1 for line in crontab_content.split("\n") if line.strip() and not line.strip().startswith("#"))
        except subprocess.CalledProcessError:
            return 0

def get_response_time():
    start_time = time.time()
    try:
        subprocess.run(["ls", "/tmp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
    except Exception:
        pass
    return round((time.time() - start_time) * 1000, 2)



def get_installed_software_count():
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["wmic", "product", "get", "name"],
                capture_output=True, text=True, check=True
            )
            lines = result.stdout.strip().splitlines()
            # Skip the first line (header), remove empty lines
            return max(0, len([line for line in lines[1:] if line.strip()]))
        except subprocess.CalledProcessError as e:
            print(f"Error running WMIC: {e}")
            return 0
    else:
        dpkg_count = 0
        snap_count = 0
        flatpak_count = 0

        # dpkg
        if os.path.exists("/usr/bin/dpkg-query"):
            try:
                result = subprocess.run(
                    ["dpkg-query", "-W", "-f=${Package}\n"],
                    capture_output=True, text=True, check=True
                )
                dpkg_packages = [line for line in result.stdout.strip().splitlines() if line]
                dpkg_count = len(dpkg_packages)
            except subprocess.CalledProcessError as e:
                print(f"Error running dpkg-query: {e}")

        # snap
        if subprocess.run(["which", "snap"], capture_output=True, text=True).returncode == 0:
            try:
                result = subprocess.run(["snap", "list"], capture_output=True, text=True, check=True)
                snap_lines = result.stdout.strip().splitlines()
                snap_count = max(0, len(snap_lines) - 1) if snap_lines else 0
            except subprocess.CalledProcessError as e:
                print(f"Error running snap list: {e}")

        # flatpak
        if subprocess.run(["which", "flatpak"], capture_output=True, text=True).returncode == 0:
            try:
                result = subprocess.run(["flatpak", "list"], capture_output=True, text=True, check=True)
                flatpak_lines = [line for line in result.stdout.strip().splitlines() if line]
                flatpak_count = len(flatpak_lines)
            except subprocess.CalledProcessError as e:
                print(f"Error running flatpak list: {e}")

        return dpkg_count + snap_count + flatpak_count


def get_disk_io_rate(interval=5):
    """
    Calculates disk read and write rate in KB/s over a given interval using psutil.
    Returns:
        tuple: (disk_read_kb_per_s, disk_write_kb_per_s)
    """
    try:
        # print("🔄 Measuring disk I/O rate...")
        # First reading
        io1 = psutil.disk_io_counters()
        # print(f"Initial read: {io1.read_bytes} bytes, write: {io1.write_bytes} bytes")

        time.sleep(interval)

        # Second reading
        io2 = psutil.disk_io_counters()
        # print(f"Later read: {io2.read_bytes} bytes, write: {io2.write_bytes} bytes")

        # Compute difference
        read_rate = (io2.read_bytes - io1.read_bytes) / 1024 / interval  # KB/s
        write_rate = (io2.write_bytes - io1.write_bytes) / 1024 / interval  # KB/s

        # print(f" Disk Read Rate: {read_rate:.2f} KB/s, Write Rate: {write_rate:.2f} KB/s")
        return round(read_rate, 2), round(write_rate, 2)

    except Exception as e:
        print(f"❌ Error getting disk IO: {e}")
        return 0, 0
    


# def get_external_devices() -> List[Dict]:
#     """Get basic information about connected USB devices.
    
#     Returns:
#         List of dictionaries containing USB device information with fields:
#         - device_id: Unique identifier for the device
#         - name: Device description/name
#         - port_number: USB port number
#         - connection_time: When the device was detected
#         - is_connected: Whether the device is currently connected
#     """
#     devices = []
#     logger = logging.getLogger(__name__)
#     current_time = datetime.now().isoformat()  # Fixed datetime usage

#     try:
#         # Get USB devices using lsusb
#         lsusb_process = subprocess.run(
#             ["lsusb"], 
#             capture_output=True, 
#             text=True, 
#             check=True
#         )
        
#         # Process each USB device
#         for line in lsusb_process.stdout.strip().split("\n"):
#             try:
#                 # Parse lsusb output
#                 match = re.match(
#                     r'Bus (\d{3}) Device (\d{3}): ID (\w{4}):(\w{4}) (.*)',
#                     line
#                 )
#                 if match:
#                     bus, device_id, vendor_id, product_id, description = match.groups()
                    
#                     device = {
#                         "device_id": f"{vendor_id}:{product_id}:{bus}:{device_id}",
#                         "name": description.strip(),
#                         "port_number": device_id,
#                         "connection_time": current_time,
#                         "is_connected": True
#                     }
                    
#                     devices.append(device)
                    
#             except (ValueError, IndexError) as e:
#                 logger.warning(f"Error parsing USB device line: {line}, Error: {e}")
                
#     except subprocess.SubprocessError as e:
#         logger.error(f"Error getting USB devices: {e}")

#     return devices

def get_external_devices() -> List[Dict]:
    """Get basic information about connected USB devices on Linux and Windows."""
    devices = []
    logger = logging.getLogger(__name__)
    current_time = datetime.now().isoformat()

    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["wmic", "path", "Win32_USBControllerDevice", "get", "Dependent"],
                capture_output=True, text=True, check=True
            )
            lines = result.stdout.strip().splitlines()[1:]  # Skip header

            for line in lines:
                try:
                    match = re.search(r'DeviceID="(.+?)"', line)
                    if match:
                        device_id = match.group(1)
                        # Use device_id as a unique identifier; name is optional
                        devices.append({
                            "device_id": device_id,
                            "name": "USB Device",
                            "port_number": "N/A",
                            "connection_time": current_time,
                            "is_connected": True
                        })
                except Exception as e:
                    logger.warning(f"Error parsing WMIC line: {line}, Error: {e}")

        except subprocess.SubprocessError as e:
            logger.error(f"Error getting USB devices on Windows: {e}")

    else:
        try:
            lsusb_process = subprocess.run(
                ["lsusb"], 
                capture_output=True, 
                text=True, 
                check=True
            )

            for line in lsusb_process.stdout.strip().split("\n"):
                try:
                    match = re.match(
                        r'Bus (\d{3}) Device (\d{3}): ID (\w{4}):(\w{4}) (.*)',
                        line
                    )
                    if match:
                        bus, device_id, vendor_id, product_id, description = match.groups()
                        devices.append({
                            "device_id": f"{vendor_id}:{product_id}:{bus}:{device_id}",
                            "name": description.strip(),
                            "port_number": device_id,
                            "connection_time": current_time,
                            "is_connected": True
                        })
                except (ValueError, IndexError) as e:
                    logger.warning(f"Error parsing USB line: {line}, Error: {e}")

        except subprocess.SubprocessError as e:
            logger.error(f"Error getting USB devices on Linux: {e}")

    return devices


_encrypted_count = 0

def _scan_encrypted_files(interval_sec: int = 300):
    """
    Background worker: every `interval_sec` seconds, walk the file system
    and update the global _encrypted_count with files matching common encrypted extensions.
    """
    global _encrypted_count
    exts = ('.gpg', '.enc', '.aes', '.pgp', '.zip', '.tar')

    if platform.system() == "Windows":
        drives = [f"{d}:/" for d in string.ascii_uppercase if os.path.exists(f"{d}:/")]

        while True:
            count = 0
            for drive in drives:
                for root, _, files in os.walk(drive, topdown=True):
                    for fname in files:
                        if fname.lower().endswith(exts):
                            count += 1
            _encrypted_count = count
            time.sleep(interval_sec)

    else:
        SKIP_PREFIXES = ('/proc', '/sys', '/dev', '/run')
        while True:
            count = 0
            for root, dirs, files in os.walk('/', topdown=True):
                if any(root.startswith(p) for p in SKIP_PREFIXES):
                    dirs[:] = []
                    continue
                for fname in files:
                    if fname.lower().endswith(exts):
                        count += 1
            _encrypted_count = count
            time.sleep(interval_sec)

# Start the background scanner
threading.Thread(target=_scan_encrypted_files, daemon=True).start()


def get_encrypted_files() -> int:
    """
    Return the most recently computed count of encrypted files.
    Instant, never blocking, always an int (0 if none or before first scan).
    """
    return _encrypted_count


def get_usb_mounts():
    """Get all mounted USB/removable devices (cross-platform)."""
    mounts = []

    if platform.system() == "Windows":
        DRIVE_REMOVABLE = 2
        try:
            for part in psutil.disk_partitions(all=False):
                drive_type = win32file.GetDriveType(part.device)
                if drive_type == DRIVE_REMOVABLE:
                    mounts.append({
                        'device': part.device,
                        'mountpoint': part.mountpoint,
                        'fstype': part.fstype
                    })
        except Exception as e:
            print(f"[Windows][USB Mounts] Error: {e}")

    else:
        for part in psutil.disk_partitions(all=False):
            if part.device.startswith('/dev/sd') and (
                part.mountpoint.startswith('/media') or part.mountpoint.startswith('/run/media')
            ):
                mounts.append({
                    'device': part.device,
                    'mountpoint': part.mountpoint,
                    'fstype': part.fstype
                })

    return mounts

def get_system_info():
    """Get basic system information in a cross-platform way."""
    try:
        username = psutil.users()[0].name if psutil.users() else "Unknown"
    except Exception:
        username = "Unknown"

    try:
        if hasattr(os, 'uname'):
            hostname = os.uname().nodename
        else:
            hostname = socket.gethostname()
    except Exception:
        hostname = "Unknown"

    return {
        "username": username,
        "hostname": hostname,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }



# def collect_usb_info():
#     USERNAME = psutil.users()[0].name if psutil.users() else "Unknown"
#     try:
#         usb_mounts = get_usb_mounts()  # this should return a list of mount paths
#         system_info = get_system_info()  # can return hostname, os info, etc.

#         data = {
#             "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
#             "username": USERNAME,
#             "usb_mounts": usb_mounts,
#             "system_info": system_info
#         }
#         return data
#     except Exception as e:
#         logging.error(f"Error collecting USB info: {e}")
#         return None

def collect_usb_info():
    try:
        USERNAME = psutil.users()[0].name if psutil.users() else "Unknown"
    except Exception:
        USERNAME = "Unknown"

    try:
        usb_mounts = get_usb_mounts()       # Already cross-platform
        system_info = get_system_info()     # Already cross-platform

        data = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "username": USERNAME,
            "usb_mounts": usb_mounts,
            "system_info": system_info
        }
        return data

    except Exception as e:
        logging.error(f"Error collecting USB info: {e}")
        return None


AUTH_LOG = "/var/log/auth.log"  # or /var/log/secure   
# Patterns
ISO_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}T[\d:.+]+).*sudo:')
SYSLOG_RE = re.compile(r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})')
SUDO_CMD_RE = re.compile(r'COMMAND=(.*)')
SUDO_FAIL_RE = re.compile(r'sudo: .*incorrect password attempts')

# Global tracker
last_seen_sudo = None

def get_recent_sudo_failures(tail_lines: int = 1000):
    """
    Detect recent failed sudo attempts in the last 5 seconds.

    Returns:
        most_recent_timestamp (str or None)
        failure_count (int)
        most_recent_command (str or None)
    """
    global last_seen_sudo

    if not os.path.exists(AUTH_LOG):
        print(f"Log file not found: {AUTH_LOG}")
        return None, 0, None

    now = datetime.now().astimezone()
    local_tz = now.tzinfo
    cutoff_time = now - timedelta(minutes=2)

    try:
        out = subprocess.check_output(
            ["tail", "-n", str(tail_lines), AUTH_LOG],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=1
        )
        lines = out.splitlines()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Error reading log: {e}")
        return None, 0, None

    failure_count = 0
    most_recent_timestamp = None
    most_recent_command = None

    for line in lines:
        ts = None

        # Parse timestamp
        iso_match = ISO_RE.match(line)
        if iso_match:
            try:
                ts = datetime.fromisoformat(iso_match.group(1)).astimezone(local_tz)
            except ValueError:
                continue
        else:
            syslog_match = SYSLOG_RE.match(line)
            if syslog_match:
                mon, day, timestr = syslog_match.groups()
                try:
                    ts = datetime.strptime(
                        f"{now.year} {mon} {int(day):02d} {timestr}",
                        "%Y %b %d %H:%M:%S"
                    ).replace(tzinfo=local_tz)
                except ValueError:
                    continue

        # Filter old entries
        if not ts or (last_seen_sudo and ts <= last_seen_sudo) or ts < cutoff_time:
            continue

        # Match sudo failure
        if "incorrect password attempts" in line:
            failure_count += 1
            most_recent_timestamp = ts.strftime("%Y-%m-%d %H:%M:%S")
            cmd_match = SUDO_CMD_RE.search(line)
            if cmd_match:
                most_recent_command = cmd_match.group(1)

    # Update last seen time
    if most_recent_timestamp:
        last_seen_sudo = ts

    return most_recent_timestamp, failure_count, most_recent_command

def get_process_remote_ip_by_user(username):
    remote_ips = set()
    try:
        for conn in psutil.net_connections(kind='inet'):
            if not conn.raddr or conn.status != psutil.CONN_ESTABLISHED:
                continue
            pid = conn.pid
            if not pid:
                continue
            try:
                proc = psutil.Process(pid)
                uid = proc.uids().real
                proc_user = pwd.getpwuid(uid).pw_name
                if proc_user == username:
                    remote_ips.add(conn.raddr.ip)
            except Exception:
                continue
    except Exception:
        pass
    return list(remote_ips) or ["unknown"]




AUTH_LOG = "/var/log/auth.log"

# 1) one regex to grab the ISO timestamp on any “unlocked login keyring” line
_UNLOCK_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[\+\-]\d{2}:\d{2}).*gkr-pam: unlocked login keyring",
    re.IGNORECASE
)

# 2) shared state + lock
_last_unlock_ts = None
_lock = threading.Lock()


def _follow_unlocks():
    """Tail -F auth.log and record the last unlock timestamp."""
    global _last_unlock_ts

    if platform.system() == "Windows":
        logging.warning("Unlock tracking is skipped on Windows.")
        return  # 🔁 Do nothing on Windows

    # Original Linux-only logic
    p = subprocess.Popen(
        ["tail", "-n", "0", "-F", AUTH_LOG],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

    for line in p.stdout:
        m = _UNLOCK_RE.search(line)
        if not m:
            continue
        try:
            ts = datetime.fromisoformat(m.group("ts"))
        except ValueError:
            continue
        with _lock:
            _last_unlock_ts = ts


# start the watcher as soon as this module is imported
threading.Thread(target=_follow_unlocks, daemon=True).start()


# For GUI unlocks, make sure you clear the stored timestamp so it only fires once:
# ensure at top you have: _last_unlock_ts: datetime | None = None, and _lock = threading.Lock()
def get_last_unlock() -> str | None:
    """
    Return the most recent unlock timestamp as 'YYYY-MM-DD HH:MM:SS' once,
    then clear it so subsequent calls return None until the next unlock.
    """
    global _last_unlock_ts
    with _lock:
        ts = _last_unlock_ts
        _last_unlock_ts = None  # clear it here
    if not ts:
        return None
    return ts.strftime("%Y-%m-%d %H:%M:%S")


_prev_disk_io = psutil.disk_io_counters()
_prev_time    = time.time()

def get_disk_io_rate():
    """
    Returns (read_rate, write_rate) in bytes/sec since the last call.
    No sleeps—very cheap.
    """
    global _prev_disk_io, _prev_time

    now     = time.time()
    elapsed = now - _prev_time or 1e-6

    curr        = psutil.disk_io_counters()
    read_rate   = (curr.read_bytes  - _prev_disk_io.read_bytes)  / elapsed
    write_rate  = (curr.write_bytes - _prev_disk_io.write_bytes) / elapsed

    _prev_disk_io = curr
    _prev_time    = now

    return read_rate, write_rate



from dateutil import parser as date_parser  # pip install python-dateutil

_script_start_time = datetime.now(timezone.utc)
_seen_users_file = "/tmp/locked_users_seen.json"

def _load_seen_users():
    if os.path.exists(_seen_users_file):
        try:
            with open(_seen_users_file, "r") as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()

def _save_seen_users(users):
    try:
        with open(_seen_users_file, "w") as f:
            json.dump(list(users), f)
    except Exception:
        pass


def get_account_lockouts(log_file: str = "/var/log/auth.log") -> list:
    """
    Parse log file for account lockouts using ISO timestamps.
    Return list of usernames that were locked after script start time.
    """
    locked_users = []
    seen_users = _load_seen_users()

    try:
        with open(log_file, "r") as f:
            for line in f:
                if "passwd" in line and (
                    ("password for '" in line and "changed by 'root'" in line)
                    or re.search(r"COMMAND=.*passwd\s+-l\s+[\w_.-]+", line)
                ):
                    match = re.match(r"^(\d{4}-\d{2}-\d{2}T[^\s]+)", line)
                    if not match:
                        continue
                    
                    try:
                        iso_ts = match.group(1)
                        log_time = date_parser.parse(iso_ts).astimezone(timezone.utc)
                        if log_time < _script_start_time:
                            continue

                        # Case A: PAM message "password for 'user' changed by 'root'"
                        m = re.search(r"password for '([^']+)' changed by 'root'", line)
                        if m:
                            user = m.group(1)
                        else:
                            # Case B: command match
                            m2 = re.search(r"COMMAND=.*passwd\s+-l\s+([A-Za-z0-9_.-]+)", line)
                            user = m2.group(1) if m2 else None

                        if user and user not in seen_users:
                            seen_users.add(user)
                            locked_users.append(user)

                    except Exception:
                        continue

    except (FileNotFoundError, PermissionError):
        return []

    _save_seen_users(seen_users)
    return locked_users


def get_new_user_creations(window_secs=5):
    """
    Detect newly created user accounts within the last `window_secs` seconds.
    First tries `journalctl` (if available) for real‐time logs;
    falls back to scanning `/var/log/auth.log` otherwise.
    Returns a deduplicated list of usernames created in that window.
    """
    # Regex to match: useradd[1234]: new user: name=USERNAME,
    useradd_re = re.compile(r"useradd\[\d+\]: new user: name=([a-zA-Z0-9_-]+),")
    new_users = set()

    # 1) Try journalctl if installed
    if shutil.which("journalctl"):
        # Use **local** time for --since
        since = (datetime.now() - timedelta(seconds=window_secs))\
                    .strftime("%Y-%m-%d %H:%M:%S")
        cmd = ["journalctl", "--since", since, "--no-pager", "-o", "short-iso"]
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=3)
            for line in out.splitlines():
                m = useradd_re.search(line)
                if m:
                    new_users.add(m.group(1))
            # return immediately—journalctl gives only recent entries
            return list(new_users)
        except Exception:
            # fallback if journalctl fails
            pass

    # 2) Fallback to /var/log/auth.log
    auth_log = "/var/log/auth.log"
    if os.path.exists(auth_log):
        window_start = datetime.now(timezone.utc) - timedelta(seconds=window_secs)
        try:
            out = subprocess.check_output(["tail", "-n", "300", auth_log],
                                          text=True, timeout=2)
            for line in out.splitlines():
                parts = line.split()
                if not parts:
                    continue
                ts_str = parts[0]
                try:
                    # parse ISO timestamp (with +TZ offset)
                    log_ts = datetime.fromisoformat(ts_str)
                except Exception:
                    continue
                # compare in UTC
                if log_ts.astimezone(timezone.utc) >= window_start:
                    m = useradd_re.search(line)
                    if m:
                        new_users.add(m.group(1))
        except Exception:
            pass

    return list(new_users)


# ─── UEBA_3: Failed Access Attempt Analysis Helpers ────────────────────────

# State timestamps so each call only sees new entries
user_failed_window_start     = datetime.now(timezone.utc)
ip_failed_window_start       = datetime.now(timezone.utc)
expired_cred_window_start    = datetime.now(timezone.utc)
dict_attack_window_start     = datetime.now(timezone.utc)


from datetime import datetime, timedelta, timezone



def get_failed_logins_by_user(window_secs: int = 5) -> Dict[str, int]:
    """
    Count failed login attempts per username in the last `window_secs` seconds
    by reading sshd entries from the journal.
    """
    cmd = [
        "journalctl", "-u", "ssh.service",
        "--since", f"-{window_secs}s",
        "--no-pager", "--output", "short"
    ]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except subprocess.SubprocessError:
        return {}

    # user_re = re.compile(r"Failed password for\s+(\S+)")
    # only match the actual "Failed password for <user>" lines
    user_re = re.compile(r"Failed password for\s+(\S+)")

    counts: Dict[str,int] = {}
    for line in out.splitlines():
        m = user_re.search(line)
        if m:
            user = m.group(1)
            counts[user] = counts.get(user, 0) + 1
    return counts

def get_failed_logins_by_ip(window_secs: int = 5) -> Dict[str, int]:
    """
    Count failed login attempts per source IP in the last `window_secs` seconds
    by reading sshd entries from the journal.
    """
    cmd = [
        "journalctl", "-u", "ssh.service",
        "--since", f"-{window_secs}s",
        "--no-pager", "--output", "short"
    ]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except subprocess.SubprocessError:
        return {}

    ip_re = re.compile(r"Failed password for.*from\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")
    counts: Dict[str,int] = {}
    for line in out.splitlines():
        m = ip_re.search(line)
        if m:
            ip = m.group(1)
            counts[ip] = counts.get(ip, 0) + 1
    return counts

def get_expired_credential_attempts(window_secs: int = 30) -> int:
    """
    Count attempts mentioning expired or disabled credentials
    in the last `window_secs` seconds via journal.
    """
    cmd = [
        "journalctl", "-u", "ssh.service",
        "--since", f"-{window_secs}s",
        "--no-pager", "--output", "short"
    ]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except subprocess.SubprocessError:
        return 0

    expired_re = re.compile(r"(?:expired|disabled)")
    count = 0
    for line in out.splitlines():
        if expired_re.search(line):
            count += 1
    return count

def get_dictionary_attack_signatures(window_secs: int = 30) -> List[str]:
    """
    Scan for >5 distinct usernames in the last `window_secs` seconds
    to flag simple dictionary-attack signatures.
    """
    cmd = [
        "journalctl", "-u", "ssh.service",
        "--since", f"-{window_secs}s",
        "--no-pager", "--output", "short"
    ]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except subprocess.SubprocessError:
        return []

    user_re = re.compile(r"Failed password for\s+(\S+)")
    users = [m.group(1) for line in out.splitlines()
                   if (m := user_re.search(line))]
    distinct = set(users)
    return list(distinct) if len(distinct) > 5 else []

def get_per_process_memory_usage(top_n=5):
    procs = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            rss = proc.info['memory_info'].rss
            procs.append({'pid': proc.info['pid'], 'name': proc.info['name'], 'rss': rss})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    procs.sort(key=lambda x: x['rss'], reverse=True)
    return procs[:top_n]


############### UEBA_4:: Unsuccessful Password Change Attempt ####################
# ─── Failed password-change tracker ────────────────────────────────────────────
AUTH_LOG = "/var/log/auth.log"          # adjust for RHEL → /var/log/secure
_last_passwd_chk = datetime.now(timezone.utc)

# sudo nano /etc/pam.d/common-password

# just add log in front of this: password        requisite                       pam_pwquality.so retry=3 log
#
#sudo apt-get update
# sudo apt-get install libpam-pwquality

# Timestamp regexes (same style used elsewhere)
_PW_ISO_RE    = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+\-]\d{2}:\d{2})")
_PW_SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")

# Content patterns that indicate a **failed** password change
# _PW_FAIL_PATTERNS = [
#     re.compile(r"pam_unix\(passwd:chauthtok\):\s+authentication failure", re.I),
#     re.compile(r"passwd\[\d+\]:\s+password.*unchanged", re.I),
#     re.compile(r"passwd:.*Authentication token manipulation error", re.I),
#     re.compile(r"passwd\[\d+\]:\s+User not known to PAM", re.I),
#     re.compile(r"BAD PASSWORD", re.I),
#     re.compile(r"passwd:.*exhausted maximum number of retries", re.I),
#     re.compile(r"passwd:.*Have exhausted maximum number of retries", re.I),

# ]
_PW_FAIL_PATTERNS = [
    re.compile(r"pam_unix\(passwd:chauthtok\):\s+authentication failure", re.I),
    re.compile(r"passwd.*password.*unchanged", re.I),
    re.compile(r"passwd:.*Authentication token manipulation error", re.I),
    re.compile(r"passwd.*User not known to PAM", re.I),
    re.compile(r"BAD PASSWORD", re.I),
    re.compile(r"passwd:.*exhausted maximum number of retries", re.I),
]

# Pull a username if one is embedded in the log line
_PW_USER_PATTERNS = [
    re.compile(r"user=([^\s]+)"),
    re.compile(r"for (?:user )?([A-Za-z0-9._-]+)"),
]

def get_failed_password_changes(
    log_file: str = AUTH_LOG,
    tail_lines: int = 400,
    window_secs: int = 300
) -> tuple[str | None, int, list[str]]:
    """
    Detect **failed password-change attempts** (e.g., bad `passwd` runs) since the
    previous call.

    Returns
    -------
    most_recent_timestamp : str | None
        ISO-like string of the latest failure seen (local tz). None if none.
    failure_count : int
        Number of new failures detected.
    users : list[str]
        Distinct usernames involved (may be empty or contain 'unknown').
    """
    global _last_passwd_chk

    if platform.system() == "Windows":
        # TODO: parse Security log for 4723/4724 failures
        return None, 0, []

    if not os.path.exists(log_file):
        return None, 0, []

    now_utc   = datetime.now(timezone.utc)
    local_tz  = datetime.now().astimezone().tzinfo
    cutoff_ts = now_utc - timedelta(seconds=window_secs)

    try:
        log_tail = subprocess.check_output(
            ["tail", "-n", str(tail_lines), log_file],
            text=True, stderr=subprocess.DEVNULL, timeout=1
        ).splitlines()
    except Exception:
        return None, 0, []

    newest_ts: datetime | None = None
    fail_cnt                    = 0
    users: set[str]             = set()

    for line in reversed(log_tail):        # iterate newest → oldest
        ts: datetime | None = None

        # ── timestamp extraction ───────────────────────────────────────────────
        m_iso = _PW_ISO_RE.search(line)
        if m_iso:
            try:
                ts = datetime.fromisoformat(m_iso.group(1)).astimezone(timezone.utc)
            except ValueError:
                pass
        else:
            m_sys = _PW_SYSLOG_RE.match(line)
            if m_sys:
                mon, day, time_str = m_sys.groups()
                year = now_utc.year
                try:
                    dt_naive = datetime.strptime(
                        f"{year} {mon} {int(day):02d} {time_str}",
                        "%Y %b %d %H:%M:%S"
                    )
                    ts = dt_naive.replace(tzinfo=local_tz).astimezone(timezone.utc)
                except ValueError:
                    pass

        # Skip if timestamp missing / outside window / already processed
        # if not ts or ts <= _last_passwd_chk or ts < cutoff_ts:
        #     continue
        # If no timestamp but it matches a fail pattern, use "now"
        # if not ts and any(pat.search(line) for pat in _PW_FAIL_PATTERNS):
        #     ts = now_utc

        # # Skip if still no timestamp / outside window / already processed
        # if not ts or ts <= _last_passwd_chk or ts < cutoff_ts:
        #     continue
        # If no timestamp but it matches a fail pattern, fake ts = now
        if not ts and any(pat.search(line) for pat in _PW_FAIL_PATTERNS):
            ts = now_utc

        # Now skip only if still no timestamp OR outside window / already processed
        if not ts:
            continue
        if ts <= _last_passwd_chk or ts < cutoff_ts:
            continue

        # ── failure-pattern match ──────────────────────────────────────────────
        if any(pat.search(line) for pat in _PW_FAIL_PATTERNS):
            fail_cnt += 1
            if not newest_ts or ts > newest_ts:
                newest_ts = ts

            # try extracting username
            extracted = None
            for upat in _PW_USER_PATTERNS:
                m_user = upat.search(line)
                if m_user:
                    extracted = m_user.group(1)
                    break
            users.add(extracted or "unknown")

    # update tracker so next call only returns new events
    _last_passwd_chk = now_utc

    ts_str = newest_ts.astimezone(local_tz).strftime("%Y-%m-%d %H:%M:%S") if newest_ts else None
    return ts_str, fail_cnt, sorted(u for u in users if u)




############### UEBA_10:: Command Execution Monitoring #################

import os
import pwd
from datetime import datetime

script_start_time = datetime.now()
_last_seen_command_time = script_start_time

def get_command_executions():
    global _last_seen_command_time
    history_file = os.path.expanduser("~/.bash_history")
    user = pwd.getpwuid(os.getuid()).pw_name
    command_entries = []

    if not os.path.exists(history_file):
        return []

    try:
        with open(history_file, "r") as f:
            lines = f.readlines()
    except Exception:
        return []

    temp_timestamp = None
    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line.startswith("#"):
            try:
                ts = int(line[1:])
                temp_timestamp = datetime.fromtimestamp(ts)
            except:
                temp_timestamp = None
        else:
            if temp_timestamp and temp_timestamp > _last_seen_command_time:
                command_entries.append({
                    "timestamp": temp_timestamp.isoformat(),
                    "user_id": user,
                    "command": line,
                    "source": "bash_history"
                })
                _last_seen_command_time = temp_timestamp
            temp_timestamp = None

    return command_entries


def get_mac_address(ip):
    try:
        # Run `ip neigh` to get ARP cache
        result = subprocess.run(['ip', 'neigh'], capture_output=True, text=True, timeout=1)
        for line in result.stdout.splitlines():
            if ip in line and "lladdr" in line:
                match = re.search(r"lladdr ([0-9a-f:]{17})", line)
                if match:
                    return match.group(1)
    except Exception:
        pass
    return "00:00:00:00:00:00"


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"
    except Exception:
        return "Unknown"





##################### UEBA_19:: Privilege Escalation Monitoring #######################

PRIV_ESCALATION_ISO_RE = re.compile(r'sudo:\s*(\S+)\s*:\s*(?:user NOT in sudoers ;|TTY=.*?; PWD=.*?; USER=.*?; COMMAND=)(.*)')
ISO_TIMESTAMP_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}T[\d:.+]+)')
SSH_LOGIN_RE = re.compile(r'sshd\[\d+\]: Accepted \S+ for (\S+) from (\d+\.\d+\.\d+\.\d+)')
def detect_privilege_escalation(tail_lines: int = 1000):
    """
    Detect both allowed and denied sudo attempts.
    """
    auth_log = "/var/log/auth.log"
    now = datetime.now().astimezone()
    cutoff = now - timedelta(seconds=5)
    escalations = []
    user_ip_map = {}

    if not os.path.exists(auth_log):
        return []

    try:
        output = subprocess.check_output(["tail", "-n", str(tail_lines), auth_log], text=True)
    except Exception:
        return []

    for line in output.splitlines():
        iso_match = ISO_TIMESTAMP_RE.match(line)
        if not iso_match:
            continue
        try:
            ts = datetime.fromisoformat(iso_match.group(1)).astimezone()
        except Exception:
            continue

        if ts < cutoff:
            continue
        
        # Match SSH login (build user-IP map)
        ssh_match = SSH_LOGIN_RE.search(line)
        if ssh_match:
            user, ip = ssh_match.groups()
            user_ip_map[user] = ip
            continue

        match = PRIV_ESCALATION_ISO_RE.search(line)
        if match:
            user = match.group(1)
            command = match.group(2).strip()
            status = "rejected" if "NOT in sudoers" in line else "allowed"
            #ip = user_ip_map.get(user, "unknown")
            ip = user_ip_map.get(user) or get_process_remote_ip_by_user(user)
            escalations.append({
                "user": user,
                "time": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "command": command,
                "status": status,
                "ip": ip
            })

    return escalations
#Here privilaged_esclation ends


# Heuristic thresholds and known good/bad process traits
SUSPECT_PORTS = {4444, 9001, 1337, 53}
SUSPECT_NAMES = {"bash", "sh", "dash", "zsh", "perl", "php", "nc", "ncat", "socat", "lua"}
KNOWN_SAFE_PROCS = {"firefox", "chrome", "code", "java", "teams", "slack", "thunderbird-bin"}

# Whitelist only your own hosts / services
SAFE_REMOTE_IPS = {
    "127.0.0.1",          # loopback
    "127.0.1.1",          # local host alias
    "10.229.40.146",      # your ethernet IP
    "192.168.137.37",     # your Wi-Fi IP
}

PROCESS_YOUNG_S = 30

# Cache to suppress duplicate alerts
RS_CACHE: dict[tuple[str, int], float] = {}  # (r_ip, r_port) -> timestamp
RS_TTL = 600  # seconds


def _safe_kill(proc) -> bool:
    """Kill proc if it exists and is ≤10 min old."""
    if not proc:
        return False
    try:
        if time.time() - proc.create_time() > 600:
            return False
        os.killpg(proc.pid, signal.SIGKILL)
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
        return False


def detect_reverse_shell_events():
    now_ts = time.time()
    reverse_shell_events = []
    killed_ppids = set()

    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
            continue

        try:
            l_ip, l_port = conn.laddr[:2]
            r_ip, r_port = conn.raddr[:2]
        except (ValueError, IndexError):
            continue

        # skip if remote IP explicitly whitelisted
        if r_ip in SAFE_REMOTE_IPS:
            continue

        # de-dup by remote endpoint
        if (r_ip, r_port) in RS_CACHE and now_ts - RS_CACHE[(r_ip, r_port)] < RS_TTL:
            continue
        RS_CACHE[(r_ip, r_port)] = now_ts

        try:
            proc = psutil.Process(conn.pid) if conn.pid else None
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proc = None
        if not proc:
            continue

        proc_name = proc.name().lower()
        if proc_name in KNOWN_SAFE_PROCS:
            continue

        cmdline = " ".join(proc.cmdline())
        create_ts = proc.create_time()
        uid = proc.uids().real
        username = pwd.getpwuid(uid).pw_name if 0 <= uid < 2**31 else "unknown"
        ppid = proc.ppid()

        heuristics = {
            "suspect_port": r_port in SUSPECT_PORTS,
            "shell_like_name": proc_name in SUSPECT_NAMES,
            "young_process": (now_ts - create_ts) <= PROCESS_YOUNG_S,
            "no_tty": proc.terminal() is None,
        }

        if sum(heuristics.values()) < 2:
            continue

        reverse_shell_events.append({
            "timestamp": datetime.fromtimestamp(now_ts, tz=timezone.utc).astimezone().isoformat(timespec="seconds"),
            "pid": conn.pid,
            "ppid": ppid,
            "uid": uid,
            "user": username,
            "process": proc_name,
            "cmdline": cmdline,
            "local": f"{l_ip}:{l_port}",
            "remote": f"{r_ip}:{r_port}",
            "remote_is_private": ipaddress.ip_address(r_ip).is_private,
            "method": "reverse_shell (outbound socket)",
            "heuristics": heuristics,
        })

        if _safe_kill(proc):
            print(f"[KILLED] Reverse shell PID={proc.pid} → {r_ip}:{r_port}")
        else:
            print(f"[SKIP] Could not kill PID={proc.pid}")

        if ppid not in killed_ppids:
            try:
                parent_proc = psutil.Process(ppid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                parent_proc = None
            if _safe_kill(parent_proc):
                killed_ppids.add(ppid)
                print(f"[KILLED] Parent process PPID={ppid}")

    return reverse_shell_events

############### UEBA_15:System Latency Monitoring################


def get_app_latency_metrics(pid):
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            cpu_times = proc.cpu_times()
            try:
                io_counters = proc.io_counters()
                total_io_bytes = io_counters.read_bytes + io_counters.write_bytes
                io_wait = total_io_bytes  # Return raw bytes (float)
            except Exception:
                io_wait = None

            startup_latency = time.time() - proc.create_time()
            response_time = cpu_times.user + cpu_times.system

            return {
                "startup_latency": round(startup_latency, 2),  # seconds
                "response_time": round(response_time, 2),      # seconds
                "io_wait_time": round(io_wait, 2) if io_wait is not None else None  # bytes
            }
    except Exception as e:
        # print(f"[DEBUG] Failed to get latency metrics for PID {pid}: {e}")
        return {
            "startup_latency": None,
            "response_time": None,
            "io_wait_time": None
        }

#################### UEBA_11::Application Usage Monitoring ###############################

def get_installed_exec_commands():
    """
    Extracts executable commands from .desktop files (from Exec= lines).
    Returns a set of lowercase base commands (e.g., 'libreoffice', 'meld').
    """
    desktop_dirs = ['/usr/share/applications', os.path.expanduser('~/.local/share/applications')]
    exec_names = set()
    exec_pattern = re.compile(r'^Exec=(\S+)')

    for path in desktop_dirs:
        if os.path.exists(path):
            for file in os.listdir(path):
                if file.endswith(".desktop"):
                    full_path = os.path.join(path, file)
                    try:
                        with open(full_path, 'r') as f:
                            for line in f:
                                match = exec_pattern.match(line)
                                if match:
                                    cmd = os.path.basename(match.group(1)).lower()
                                    exec_names.add(cmd)
                    except Exception:
                        continue
    return exec_names

INSTALLED_EXEC_NAMES = get_installed_exec_commands()
# print(sorted(INSTALLED_EXEC_NAMES))

# Background/system services to exclude explicitly
BACKGROUND_NAMES = {
    "gnome-shell", "gnome-session-binary", "gnome-remote-desktop-daemon",
    "xdg-desktop-portal-gtk", "xdg-desktop-portal-gnome", "ibus-extension-gtk3",
    "evolution-alarm-notify", "snap", "gnome-settings-daemon",
    "dbus-daemon", "gjs", "bash", "python", "update-notifier",
    "networkd-dispatcher", "unattended-upgrade", "pipewire",
    "pipewire-pulse", "wireplumber", "gdm-wayland-session",
    "gnome-keyring-daemon", "xwayland", "snapd-desktop-integration",
    "networkd-dispat", "unattended-upgr", "ibus-daemon", "crashhelper","check-new-relea",
    "containerd", "containerd-shim-runc-v2", "fc-cache",
    "systemd", "udisksd", "gvfsd", "gvfs-udisks2-volume-monitor",
    "whoopsie", "polkitd"
}

def track_application_usage(poll_interval=5):
    
    # Prime all processes and cache the proc objects
    primed_procs = {}
    for proc in psutil.process_iter(attrs=["pid", "name", "username"]):
        try:
            proc.cpu_percent(None)
            primed_procs[proc.pid] = proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    time.sleep(1)


    active_processes = {}

    while True:
        current_pids = set()
        now = datetime.now()

        total_processes = 0
        matched_apps = 0
        current_app_names = set()

        for proc in psutil.process_iter(attrs=[
        "pid", "name", "username", "ppid", "cmdline",
        "memory_percent", "terminal", "create_time"
        ]):
            try:
                info = proc.info
                total_processes += 1
                pid = info["pid"]
                ppid = info.get("ppid")
                current_pids.add(pid)

                if info["username"] is None:
                    continue

                name = info.get("name", "").lower()
                cmdline = info.get("cmdline", [])

                # Safely extract executable base name
                exe_base = os.path.basename(cmdline[0]).lower() if isinstance(cmdline, (list, tuple)) and cmdline else ""

                # Safely join full command line
                full_cmd = " ".join(cmdline) if isinstance(cmdline, (list, tuple)) else ""

                # Normalize for filtering
                normalized_exe = exe_base.strip().lower()
                normalized_name = name.strip().lower()

                # Skip known background/system apps
                if normalized_name in BACKGROUND_NAMES or normalized_exe in BACKGROUND_NAMES:
                    continue

                # Skip known subprocesses used by browsers/editors
                skip_tokens = [
                    "--type=", "-contentproc", "tsserver.js", "typingsInstaller.js",
                    "jsonServerMain", "crashpad_handler", "WebExtensions", "Socket Process",
                    "RDD Process", "Isolated Web Co", "Privileged Cont", "Web Content"
                ]
                if any(token in full_cmd or token in normalized_name for token in skip_tokens):
                    continue

                #  Keep heuristics for Snap, AppImage, etc.
                is_user_app = (
                    normalized_exe in INSTALLED_EXEC_NAMES or
                    normalized_name in INSTALLED_EXEC_NAMES or
                    full_cmd.startswith("/snap/") or
                    "/snap/" in full_cmd or
                    "/opt/" in full_cmd or
                    ".AppImage" in full_cmd or
                    "/usr/bin/" in full_cmd
                )

                if not is_user_app:
                    continue

                #  Main user-facing application
                matched_apps += 1
                current_app_names.add(name or exe_base)

                # Track status as active/inactive based on recent usage
                # cpu = info.get("cpu_percent", 0.0)
                # try:
                #     cpu = proc.cpu_percent(interval=0.1)
                # except (psutil.NoSuchProcess, psutil.AccessDenied):
                #     cpu = 0.0
                try:
                    primed_proc = primed_procs.get(proc.pid)
                    if primed_proc:
                        cpu = primed_proc.cpu_percent(interval=None)  # ← second call, now gives real value
                    else:
                        cpu = proc.cpu_percent(interval=None)  # fallback
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    cpu = 0.0
                mem = info.get("memory_percent", 0.0)
                active_status = "active" if cpu > 0.5 or mem > 0.5 else "inactive"

                if pid not in active_processes:
                    active_processes[pid] = {
                        "username": info["username"],
                        "process_name": info["name"],
                        "pid": pid,
                        "ppid": ppid,
                        "cmdline": full_cmd,
                        "terminal": info.get("terminal"),
                        "status": active_status,
                        "cpu_percent": cpu,
                        "memory_percent": mem,
                        "start_time": datetime.fromtimestamp(info["create_time"]),
                        "last_updated": now,
                        "reported": False  #  used for deduplication
                    }
                else:
                    # Update dynamic info for still-active apps
                    active_processes[pid]["cpu_percent"] = cpu
                    active_processes[pid]["memory_percent"] = mem
                    active_processes[pid]["status"] = active_status
                    active_processes[pid]["last_updated"] = now

            except (psutil.NoSuchProcess, psutil.AccessDenied, IndexError):
                continue

        for pid, record in active_processes.items():
            if not record["reported"]:
                latency = get_app_latency_metrics(pid)
                yield {
                    **record,
                    **latency,
                    "event": "launch",
                    "timestamp": record["last_updated"]
                }
                record["reported"] = True  #  prevent re-yield

        # Detect and yield exits
        for pid in list(active_processes.keys()):
            if pid not in current_pids:
                record = active_processes.pop(pid)
                record["end_time"] = now
                record["duration_secs"] = (now - record["start_time"]).total_seconds()
                record["timestamp"] = now
                record["event"] = "exit"

                latency = get_app_latency_metrics(pid)
                record.update(latency)

                yield record

        time.sleep(poll_interval)


#################### UEBA_12::Process Creation and Execution Monitoring ###############################

def track_process_executions(poll_interval=5):
    """
    Generator that yields two kinds of events:
    1. process_created — immediately on detection
    2. process_exited — with end time and duration

    Only logs user-triggered processes, suppresses repetitive background events.
    """
    seen_pids = set(psutil.pids())
    process_start_times = {}
    recent_signatures = {}
    signature_ttl = 15  # seconds

    while True:
        now = time.time()
        current_pids = set(psutil.pids())
        new_pids = current_pids - seen_pids

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                with proc.oneshot():
                    parent_pid = proc.ppid()
                    parent_name = psutil.Process(parent_pid).name() if parent_pid in psutil.pids() else "unknown"
                    grandparent_pid = psutil.Process(parent_pid).ppid() if parent_pid in psutil.pids() else None
                    grandparent_name = psutil.Process(grandparent_pid).name() if grandparent_pid and grandparent_pid in psutil.pids() else "unknown"
                    terminal = proc.terminal()
                    start_time = proc.create_time()

                    cmdline = proc.cmdline()
                    cmd_string = ' '.join(cmdline)
                    signature = (proc.name(), cmd_string)

                    # Deduplicate known noisy background processes
                    last_seen = recent_signatures.get(signature)
                    if last_seen and now - last_seen < signature_ttl:
                        continue
                    recent_signatures[signature] = now

                    info = {
                        "event": "process_created",
                        "timestamp": datetime.utcnow().isoformat(),
                        "pid": pid,
                        "ppid": parent_pid,
                        "process_name": proc.name(),
                        "parent_name": parent_name,
                        "user": proc.username(),
                        "cmdline": cmdline,
                        "start_time": datetime.fromtimestamp(start_time).isoformat(),
                        "status": proc.status(),
                        "has_terminal": terminal is not None,
                        "is_interactive": terminal is not None,
                        "terminal": terminal,
                        "is_likely_user_process": (
                            terminal is not None or
                            parent_name in {"bash", "zsh", "gnome-terminal", "xfce4-terminal", "konsole","code"}
                        ),
                        "likely_background_loop": (
                            "cpuUsage.sh" in proc.name() and
                            parent_name == "sh" and
                            "code" in grandparent_name
                        )
                    }
                    #print(f"[DEBUG] NEW PID: {pid}, NAME: {info['process_name']}, PARENT: {parent_name}, TERMINAL: {terminal}")

                    #  Only emit user-triggered events
                    if not info["is_likely_user_process"]:
                        continue

                    #  Suppress common noise
                    if info["process_name"] in {"sh", "sleep", "tracker-extract-3", "cpuUsage.sh"}:
                        continue

                    process_start_times[pid] = (start_time, info.copy())
                    seen_pids.add(pid)
                    yield info

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Check for exited processes
        ended_pids = []
        for pid, (start_time, info) in process_start_times.items():
            if not psutil.pid_exists(pid):
                end_time = time.time()
                yield {
                    "event": "process_exited",
                    "timestamp": datetime.utcnow().isoformat(),
                    "pid": pid,
                    "end_time": datetime.fromtimestamp(end_time).isoformat(),
                    "execution_duration": round(end_time - start_time, 3),
                    "start_time": info["start_time"],
                    "process_name": info["process_name"],
                    "user": info["user"],
                    "cmdline": info["cmdline"],
                    "parent_name": info["parent_name"],
                    "ppid": info["ppid"],
                    "is_interactive": info["is_interactive"],
                    "has_terminal": info["has_terminal"],
                    "is_likely_user_process": info["is_likely_user_process"],
                    "likely_background_loop": info["likely_background_loop"]
                }
                ended_pids.append(pid)

        for pid in ended_pids:
            process_start_times.pop(pid, None)

        recent_signatures = {
            sig: ts for sig, ts in recent_signatures.items()
            if now - ts < signature_ttl
        }

        seen_pids = current_pids
        time.sleep(poll_interval)



_active_processes = {}
def is_user_application(proc):
    try:
        if proc.username() != psutil.users()[0].name:
            return False
        if proc.ppid() == 1:
            return True
        if proc.terminal():  # Interactive terminal
            return True
        # Allow known GUI apps launched by user session
        name = proc.name().lower()
        return any(x in name for x in [
            "code", "brave", "chrome", "firefox", "pgadmin", "java", "gnome", "terminal"
        ])
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def get_per_process_latency_sessions(poll_interval=5):
    global _active_processes

    while True:
        current_pids = set()
        session_data = []

        for proc in psutil.process_iter(['pid', 'name', 'username', 'create_time']):
            try:
                if not is_user_application(proc):
                    continue

                pid = proc.info['pid']
                current_pids.add(pid)

                if pid not in _active_processes:
                    _active_processes[pid] = {
                        "pid": pid,
                        "name": proc.info.get('name'),
                        "username": proc.info.get('username'),
                        "create_time": proc.info.get('create_time'),
                        "start_time": datetime.fromtimestamp(proc.info.get('create_time')),
                        "cpu_times": proc.cpu_times(),
                        "memory_info": proc.memory_info(),
                        "io_counters": proc.io_counters() if proc.io_counters() else None,
                        "ctx_switches": proc.num_ctx_switches() if hasattr(proc, 'num_ctx_switches') else None,
                    }
                else:
                    pinfo = _active_processes[pid]
                    pinfo["cpu_times"] = proc.cpu_times()
                    pinfo["memory_info"] = proc.memory_info()
                    pinfo["io_counters"] = proc.io_counters() if proc.io_counters() else None
                    pinfo["ctx_switches"] = proc.num_ctx_switches() if hasattr(proc, 'num_ctx_switches') else None

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        ended_pids = set(_active_processes.keys()) - current_pids
        for pid in ended_pids:
            info = _active_processes.pop(pid)
            end_time = datetime.now()
            duration = (end_time - info['start_time']).total_seconds()

            io_read = info['io_counters'].read_bytes if info['io_counters'] else None
            io_write = info['io_counters'].write_bytes if info['io_counters'] else None
            rss = info['memory_info'].rss if info['memory_info'] else None
            cpu_user = info['cpu_times'].user if info['cpu_times'] else None
            cpu_system = info['cpu_times'].system if info['cpu_times'] else None
            ctx_vol = info['ctx_switches'].voluntary if info['ctx_switches'] else None
            ctx_invol = info['ctx_switches'].involuntary if info['ctx_switches'] else None

            session_data.append({
                "pid": pid,
                "process_name": info['name'],
                "username": info['username'],
                "start_time": info['start_time'].isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": duration,
                "cpu_user_time": cpu_user,
                "cpu_system_time": cpu_system,
                "memory_rss": rss,
                "io_read_bytes": io_read,
                "io_write_bytes": io_write,
                "ctx_switches_voluntary": ctx_vol,
                "ctx_switches_involuntary": ctx_invol
            })

        if session_data:
            yield session_data

        time.sleep(poll_interval)
