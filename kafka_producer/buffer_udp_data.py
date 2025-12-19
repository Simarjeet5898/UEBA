"""
buffer_udp_data.py

Client-side UDP buffering with SQLite store-and-forward semantics.

Core idea:
- Intercept UDP sends to (SERVER_IP, SERVER_PORT)
- If message is "data" -> persist to SQLite queue (durable)
- Background sender drains queue and sends to server with msg_id envelope
- Server must ACK (msg_id) back to client ACK_PORT
- On ACK, client deletes from queue

This module is intended to be enabled from producer_main.py before importing
producer modules, so their sockets inherit the patched sendto behavior.
"""

from __future__ import annotations

import json
import os
import queue
import random
import socket
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple


# -----------------------------
# Defaults / constants
# -----------------------------
DEFAULT_DB_PATH = "/var/lib/ueba/udp_buffer_spool.db"
DEFAULT_DB_DIR = "/var/lib/ueba"
DEFAULT_TABLE = "udp_outbox"

# Types that should bypass buffering (control-plane)
DEFAULT_BYPASS_TYPES = {
    "heartbeat",
    "pong",
    "ping",
    "CLIENT_REGISTER",
    "system_status",
    # if you have other control types, add here
}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _safe_mkdir(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        # If cannot create, caller will hit DB open error and see logs there.
        pass


# -----------------------------
# SQLite Queue
# -----------------------------
class SQLiteOutbox:
    """
    Durable FIFO-ish outbox.
    Multiple producer threads can enqueue.
    One sender thread dequeues.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH, table: str = DEFAULT_TABLE):
        self.db_path = db_path
        self.table = table
        db_dir = os.path.dirname(db_path)
        if db_dir:
            _safe_mkdir(db_dir)

        self._init_db()

        # lightweight lock for SQLite writes from multiple threads
        # (SQLite itself serializes, but lock reduces busy errors)
        self._lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA busy_timeout=30000;")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self.table} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    msg_id TEXT NOT NULL UNIQUE,
                    created_ms INTEGER NOT NULL,
                    last_try_ms INTEGER,
                    try_count INTEGER NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL
                );
                """
            )
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.table}_created ON {self.table}(created_ms);")
            conn.commit()
        finally:
            conn.close()

    def enqueue(self, envelope: Dict[str, Any]) -> str:
        """
        Insert into outbox. Returns msg_id.
        """
        msg_id = envelope.get("msg_id") or str(uuid.uuid4())
        envelope["msg_id"] = msg_id

        payload = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)
        created_ms = _now_ms()

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    f"INSERT OR IGNORE INTO {self.table}(msg_id, created_ms, payload_json) VALUES(?,?,?)",
                    (msg_id, created_ms, payload),
                )
                conn.commit()
            finally:
                conn.close()

        return msg_id

    def peek_batch(self, limit: int = 200) -> list[tuple[int, str, str]]:
        """
        Returns [(row_id, msg_id, payload_json), ...] oldest first.
        Does not remove them yet.
        """
        conn = self._connect()
        try:
            cur = conn.execute(
                f"SELECT id, msg_id, payload_json FROM {self.table} ORDER BY id ASC LIMIT ?",
                (limit,),
            )
            return cur.fetchall()
        finally:
            conn.close()

    def mark_try(self, row_ids: list[int]) -> None:
        if not row_ids:
            return
        now = _now_ms()
        with self._lock:
            conn = self._connect()
            try:
                # Mark try_count++ and last_try_ms
                conn.executemany(
                    f"UPDATE {self.table} SET try_count = try_count + 1, last_try_ms = ? WHERE id = ?",
                    [(now, rid) for rid in row_ids],
                )
                conn.commit()
            finally:
                conn.close()

    def delete_by_msg_ids(self, msg_ids: list[str]) -> int:
        if not msg_ids:
            return 0
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.executemany(
                    f"DELETE FROM {self.table} WHERE msg_id = ?",
                    [(m,) for m in msg_ids],
                )
                conn.commit()
                return cur.rowcount if cur is not None else 0
            finally:
                conn.close()

    def count(self) -> int:
        conn = self._connect()
        try:
            cur = conn.execute(f"SELECT COUNT(*) FROM {self.table}")
            return int(cur.fetchone()[0])
        finally:
            conn.close()

    def delete_older_than_ms(self, cutoff_ms: int) -> int:
        """
        Delete buffered rows older than cutoff_ms.
        """
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    f"DELETE FROM {self.table} WHERE created_ms < ?",
                    (int(cutoff_ms),),
                )
                conn.commit()
                return cur.rowcount if cur is not None else 0
            finally:
                conn.close()


# -----------------------------
# ACK Listener
# -----------------------------
class AckListener(threading.Thread):
    """
    Listens for ACK messages from server:
      {"type":"ack","msg_id":"..."}
    """

    def __init__(
        self,
        outbox: SQLiteOutbox,
        listen_ip: str,
        listen_port: int,
        stop_event: threading.Event,
        ack_queue: "queue.Queue[str]",
        name: str = "UEBA-AckListener",
    ):
        super().__init__(name=name, daemon=True)
        self.outbox = outbox
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.stop_event = stop_event
        self.ack_queue = ack_queue
        self.sock: Optional[socket.socket] = None

    def run(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.listen_ip, self.listen_port))
        self.sock.settimeout(0.5)

        while not self.stop_event.is_set():
            try:
                data, _addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            # Parse JSON
            try:
                msg = json.loads(data.decode("utf-8", errors="ignore"))
            except Exception:
                continue

            # Only ACK messages matter here
            if not isinstance(msg, dict) or msg.get("type") != "ack":
                continue

            msg_id = msg.get("msg_id")
            print(f"[AckListener] ACK received: msg_id={msg_id}")

            if not msg_id:
                continue

            # Push into in-memory queue; sender thread will delete in batches
            try:
                self.ack_queue.put_nowait(msg_id)
            except Exception:
                # If queue is full, fall back to direct delete (rare)
                try:
                    self.outbox.delete_by_msg_ids([msg_id])
                except Exception:
                    pass

        # Close socket on exit
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass



# -----------------------------
# Sender Loop
# -----------------------------
class Sender(threading.Thread):
    """
    Drains outbox and sends to server.
    Deletes only on ACK.
    """

    # def __init__(
    #     self,
    #     outbox: SQLiteOutbox,
    #     server_addr: Tuple[str, int],
    #     stop_event: threading.Event,
    #     ack_queue: "queue.Queue[str]",
    #     batch_size: int = 200,
    #     idle_sleep_s: float = 0.15,
    #     max_backoff_s: float = 30.0,
    #     name: str = "UEBA-BufferedSender",
    # ):
    def __init__(
        self,
        outbox: SQLiteOutbox,
        server_addr: Tuple[str, int],
        stop_event: threading.Event,
        ack_queue: "queue.Queue[str]",
        ack_bind: Tuple[str, int],
        batch_size: int = 200,
        idle_sleep_s: float = 0.15,
        max_backoff_s: float = 30.0,
        name: str = "UEBA-BufferedSender",
    ):
        super().__init__(name=name, daemon=True)
        self.outbox = outbox
        self.server_addr = server_addr
        self.stop_event = stop_event
        self.ack_queue = ack_queue
        self.batch_size = batch_size
        self.idle_sleep_s = idle_sleep_s
        self.max_backoff_s = max_backoff_s

        # self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # self._backoff = 0.5
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # IMPORTANT: bind sender socket to ACK listener port so ACKs return to this port
        try:
            self._sock.bind(ack_bind)
        except Exception as e:
            print(f"[Sender] bind failed on {ack_bind} -> {e}")

        self._backoff = 0.5


    def _drain_acks(self) -> None:
        """
        Batch-delete ACKed messages to reduce SQLite churn.
        """
        msg_ids: list[str] = []
        while True:
            try:
                msg_ids.append(self.ack_queue.get_nowait())
                if len(msg_ids) >= 500:
                    break
            except queue.Empty:
                break

        if msg_ids:
            self.outbox.delete_by_msg_ids(msg_ids)

    def run(self) -> None:
        # optional retention (0 = keep forever)
        retention_s = getattr(self, "max_buffer_age_seconds", 0)
        last_retention_check = 0.0
        retention_check_every = 5.0  # seconds

        while not self.stop_event.is_set():
            # 1) apply ACK deletes first
            self._drain_acks()

            # 2) retention cleanup (if enabled)
            if retention_s and retention_s > 0:
                now = time.time()
                if now - last_retention_check >= retention_check_every:
                    try:
                        self.outbox.delete_older_than(retention_s)
                    except Exception:
                        pass
                    last_retention_check = now

            # 3) send pending batch
            batch = self.outbox.peek_batch(self.batch_size)
            if not batch:
                self._backoff = 0.5
                time.sleep(self.idle_sleep_s)
                continue

            row_ids = [rid for rid, _mid, _payload in batch]
            self.outbox.mark_try(row_ids)

            try:
                for _rid, _mid, payload_json in batch:
                    # print(f"[Sender] sending msg_id={_mid} -> {self.server_addr}")
                    # print("[Sender][DEBUG] payload_json =", payload_json)
                    self._sock.sendto(payload_json.encode("utf-8"), self.server_addr)

                # SUCCESS: do NOT backoff. Keep draining fast.
                self._backoff = 0.5
                time.sleep(0.01)

            except Exception:
                # FAILURE: backoff and retry
                print(f"[Sender][ERROR] send failed to {self.server_addr} -> {e}")
                self._backoff = min(self.max_backoff_s, max(1.0, self._backoff * 2.0))
                time.sleep(self._backoff + random.random() * 0.3)

        # final ACK drain on exit
        try:
            self._drain_acks()
        except Exception:
            pass



# -----------------------------
# sendto interception / patching
# -----------------------------
@dataclass
class BufferConfig:
    server_ip: str
    server_port: int
    client_id: str
    ack_listen_ip: str = "0.0.0.0"
    ack_listen_port: int = 6010
    db_path: str = DEFAULT_DB_PATH
    bypass_types: Optional[set[str]] = None

    # sender tuning
    batch_size: int = 200
    max_buffer_age_seconds: int = 0



# class BufferedUDP:
#     """
#     Main façade:
#     - owns outbox, sender, ack listener
#     - patches socket.socket.sendto so existing producers require minimal/no edits
#     """

#     def __init__(self, cfg: BufferConfig, stop_event: threading.Event):
#         self.cfg = cfg
#         self.stop_event = stop_event
#         self.outbox = SQLiteOutbox(cfg.db_path)
#         self.ack_queue: "queue.Queue[str]" = queue.Queue(maxsize=50000)

#         self.sender = Sender(
#             outbox=self.outbox,
#             server_addr=(cfg.server_ip, cfg.server_port),
#             stop_event=stop_event,
#             ack_queue=self.ack_queue,
#             ack_bind=(cfg.ack_listen_ip, cfg.ack_listen_port),
#             batch_size=cfg.batch_size,
#         )
#         self._sender_sock_fd = self.sender._sock.fileno()

#         # NEW: retention value from config (0 => infinite)
#         self.sender.max_buffer_age_seconds = cfg.max_buffer_age_seconds

#         self.ack_listener = AckListener(
#             outbox=self.outbox,
#             listen_ip=cfg.ack_listen_ip,
#             listen_port=cfg.ack_listen_port,
#             stop_event=stop_event,
#             ack_queue=self.ack_queue,
#         )

#         self._patched = False
#         self._orig_sendto = None 

#         self.bypass_types = cfg.bypass_types or DEFAULT_BYPASS_TYPES


#     def start(self) -> None:
#         """
#         Start background threads (ACK listener + sender).
#         """
#         self.ack_listener.start()
#         self.sender.start()

#     def _should_bypass(self, raw_bytes: bytes) -> bool:
#         """
#         Bypass buffering for control-plane messages to prevent replaying stale heartbeats/pongs.
#         """
#         try:
#             obj = json.loads(raw_bytes.decode("utf-8", errors="ignore"))
#         except Exception:

#             return True

#         t = obj.get("type")
#         if t in self.bypass_types:
#             return True

#         event = obj.get("event")
#         if isinstance(event, str) and (
#             event.startswith("system_") or event.startswith("subsystem_")
#             or event.startswith("config_change_") or event.startswith("logging_")
#         ):
#             return True

#         return False

#     def _wrap_payload(self, raw_bytes: bytes) -> Dict[str, Any]:
#         """
#         Wrap existing JSON into an envelope (adds msg_id + client_id).
#         """
#         try:
#             payload = json.loads(raw_bytes.decode("utf-8", errors="ignore"))
#         except Exception:
#             payload = {"raw": raw_bytes.decode("utf-8", errors="ignore")}

#         if (
#             isinstance(payload, dict)
#             and payload.get("type") == "buffered_event"
#             and "msg_id" in payload
#             and "client_id" in payload
#             and "payload" in payload
#         ):
#             return payload

#         envelope = {
#             "type": "buffered_event",
#             "client_id": self.cfg.client_id,
#             "msg_id": str(uuid.uuid4()),
#             "sent_ts_ms": _now_ms(),
#             "payload": payload,
#         }
#         return envelope

#     def patch_sendto(self) -> None:
#         if self._patched:
#             return

#         self._orig_sendto = socket.socket.sendto
#         self._orig_send = socket.socket.send

#         server_ip = self.cfg.server_ip
#         server_port = self.cfg.server_port

#         def patched_sendto(sock_obj: socket.socket, data: bytes, addr: Tuple[str, int], *args, **kwargs):
#             try:
#                 dst_ip, dst_port = addr[0], int(addr[1])
#             except Exception:
#                 return self._orig_sendto(sock_obj, data, addr, *args, **kwargs)

#             if dst_port == server_port:
#                 if self._should_bypass(data):
#                     return self._orig_sendto(sock_obj, data, addr, *args, **kwargs)

#                 envelope = self._wrap_payload(data)
#                 self.outbox.enqueue(envelope)
#                 return len(data)

#             return self._orig_sendto(sock_obj, data, addr, *args, **kwargs)

#         def patched_send(sock_obj: socket.socket, data: bytes, *args, **kwargs):
#             try:
#                 dst_ip, dst_port = sock_obj.getpeername()
#                 dst_port = int(dst_port)
#             except Exception:
#                 return self._orig_send(sock_obj, data, *args, **kwargs)

#             if dst_port == server_port:
#                 if self._should_bypass(data):
#                     return self._orig_send(sock_obj, data, *args, **kwargs)

#                 envelope = self._wrap_payload(data)
#                 self.outbox.enqueue(envelope)
#                 return len(data)

#             return self._orig_send(sock_obj, data, *args, **kwargs)

#         socket.socket.sendto = patched_sendto
#         socket.socket.send = patched_send
#         self._patched = True


#     # def unpatch_sendto(self) -> None:
#     #     if self._patched and self._orig_sendto is not None:
#     #         socket.socket.sendto = self._orig_sendto  # type: ignore
#     #         self._patched = False

#     def unpatch_sendto(self) -> None:
#         if not self._patched:
#             return
#         if self._orig_sendto is not None:
#             socket.socket.sendto = self._orig_sendto
#         if hasattr(self, "_orig_send") and self._orig_send is not None:
#             socket.socket.send = self._orig_send
#         self._patched = False
class BufferedUDP:
    """
    Main façade:
    - owns outbox, sender, ack listener
    - patches socket.socket.sendto/send so existing producers require minimal/no edits
    - IMPORTANT: bypass buffering for Sender's own socket to avoid self-rebuffer loops
    """

    def __init__(self, cfg: BufferConfig, stop_event: threading.Event):
        self.cfg = cfg
        self.stop_event = stop_event

        self.outbox = SQLiteOutbox(cfg.db_path)
        self.ack_queue: "queue.Queue[str]" = queue.Queue(maxsize=50000)

        self.sender = Sender(
            outbox=self.outbox,
            server_addr=(cfg.server_ip, cfg.server_port),
            stop_event=stop_event,
            ack_queue=self.ack_queue,
            ack_bind=(cfg.ack_listen_ip, cfg.ack_listen_port),
            batch_size=cfg.batch_size,
        )
        # ✅ used to bypass buffering for sender's own UDP socket
        self._sender_sock_fd = self.sender._sock.fileno()

        # retention value from config (0 => infinite)
        self.sender.max_buffer_age_seconds = cfg.max_buffer_age_seconds

        self.ack_listener = AckListener(
            outbox=self.outbox,
            listen_ip=cfg.ack_listen_ip,
            listen_port=cfg.ack_listen_port,
            stop_event=stop_event,
            ack_queue=self.ack_queue,
        )

        self.bypass_types = cfg.bypass_types or DEFAULT_BYPASS_TYPES

        self._patched = False
        self._orig_sendto = None
        self._orig_send = None

    def start(self) -> None:
        """Start background threads (ACK listener + sender)."""
        self.ack_listener.start()
        self.sender.start()

    def _should_bypass(self, raw_bytes: bytes) -> bool:
        """Bypass buffering for control-plane messages."""
        try:
            obj = json.loads(raw_bytes.decode("utf-8", errors="ignore"))
        except Exception:
            return True

        t = obj.get("type")
        if t in self.bypass_types:
            return True

        event = obj.get("event")
        if isinstance(event, str) and (
            event.startswith("system_")
            or event.startswith("subsystem_")
            or event.startswith("config_change_")
            or event.startswith("logging_")
        ):
            return True

        return False

    def _wrap_payload(self, raw_bytes: bytes) -> Dict[str, Any]:
        """Wrap existing JSON into an envelope (adds msg_id + client_id)."""
        try:
            payload = json.loads(raw_bytes.decode("utf-8", errors="ignore"))
        except Exception:
            payload = {"raw": raw_bytes.decode("utf-8", errors="ignore")}

        # If already wrapped, return as-is
        if (
            isinstance(payload, dict)
            and payload.get("type") == "buffered_event"
            and "msg_id" in payload
            and "client_id" in payload
            and "payload" in payload
        ):
            return payload

        return {
            "type": "buffered_event",
            "client_id": self.cfg.client_id,
            "msg_id": str(uuid.uuid4()),
            "sent_ts_ms": _now_ms(),
            "payload": payload,
        }

    def patch_sendto(self) -> None:
        if self._patched:
            return

        self._orig_sendto = socket.socket.sendto
        self._orig_send = socket.socket.send

        server_ip = self.cfg.server_ip
        server_port = self.cfg.server_port

        def patched_sendto(
            sock_obj: socket.socket,
            data: bytes,
            addr: Tuple[str, int],
            *args,
            **kwargs,
        ):
            # ✅ BYPASS sender socket (prevent re-buffering buffered replays)
            try:
                if sock_obj.fileno() == self._sender_sock_fd:
                    return self._orig_sendto(sock_obj, data, addr, *args, **kwargs)
            except Exception:
                pass

            try:
                dst_ip, dst_port = addr[0], int(addr[1])
            except Exception:
                return self._orig_sendto(sock_obj, data, addr, *args, **kwargs)

            # Intercept messages going to the server ingest port
            if dst_port == server_port and dst_ip == server_ip:
                if self._should_bypass(data):
                    return self._orig_sendto(sock_obj, data, addr, *args, **kwargs)

                envelope = self._wrap_payload(data)
                self.outbox.enqueue(envelope)
                return len(data)

            return self._orig_sendto(sock_obj, data, addr, *args, **kwargs)

        def patched_send(sock_obj: socket.socket, data: bytes, *args, **kwargs):
            # ✅ BYPASS sender socket (prevent re-buffering buffered replays)
            try:
                if sock_obj.fileno() == self._sender_sock_fd:
                    return self._orig_send(sock_obj, data, *args, **kwargs)
            except Exception:
                pass

            try:
                dst_ip, dst_port = sock_obj.getpeername()
                dst_port = int(dst_port)
            except Exception:
                return self._orig_send(sock_obj, data, *args, **kwargs)

            if dst_port == server_port and dst_ip == server_ip:
                if self._should_bypass(data):
                    return self._orig_send(sock_obj, data, *args, **kwargs)

                envelope = self._wrap_payload(data)
                self.outbox.enqueue(envelope)
                return len(data)

            return self._orig_send(sock_obj, data, *args, **kwargs)

        socket.socket.sendto = patched_sendto
        socket.socket.send = patched_send
        self._patched = True

    def unpatch_sendto(self) -> None:
        if not self._patched:
            return
        if self._orig_sendto is not None:
            socket.socket.sendto = self._orig_sendto
        if self._orig_send is not None:
            socket.socket.send = self._orig_send
        self._patched = False



# Convenience initializer
def init_buffering(cfg: BufferConfig, stop_event: threading.Event) -> BufferedUDP:
    """
    Create, patch, and start buffering transport.
    Caller should invoke this BEFORE importing producer modules that create sockets.
    """
    buffered = BufferedUDP(cfg, stop_event)
    buffered.patch_sendto()
    buffered.start()
    return buffered
