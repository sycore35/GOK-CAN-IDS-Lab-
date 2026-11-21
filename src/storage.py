"""
GÖK CAN-IDS Lab — SQLite Event Store & Incident Exporter.
Zero external database dependencies.
"""
import sqlite3
import json
import threading
import time
import os
from typing import Dict, Any, List, Optional
from src.can_frame import CANFrame
from src.can_ids import CANAlert


class CANStorage:
    """Local SQLite repository for CAN traffic, IDS security alerts, and audit trails."""

    FLUSH_INTERVAL_S = 0.5      # simulation ticks are buffered and written together (one fsync per ~12 ticks)
    FLUSH_ROWS = 2000

    def __init__(self, db_path: str = "data/can_events.db", max_frames: int = 20000, max_alerts: int = 20000,
                 max_audit: int = 2000):
        self.db_path = db_path
        self.max_frames, self.max_alerts, self.max_audit = max_frames, max_alerts, max_audit
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.DatabaseError:
            pass
        self._init_db()
        self._buf_frames: List[tuple] = []
        self._buf_alerts: List[tuple] = []
        self._last_flush = time.monotonic()
        self._writes = 0
        self.total_alerts = self.count_alerts()

    class _ConnCtx:
        def __init__(self, store):
            self.store = store

        def __enter__(self):
            self.store._lock.acquire()
            return self.store._conn

        def __exit__(self, et, ev, tb):
            try:
                if et is None:
                    self.store._conn.commit()
                else:
                    self.store._conn.rollback()
            finally:
                self.store._lock.release()
            return False

    def _get_conn(self) -> "CANStorage._ConnCtx":
        """Shared connection guarded by a lock; commits on success."""
        return CANStorage._ConnCtx(self)

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS can_frames (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    arbitration_id INTEGER,
                    hex_id TEXT,
                    dlc INTEGER,
                    data_hex TEXT,
                    bus_load_pct REAL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ids_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    rule_id TEXT,
                    rule_name TEXT,
                    severity TEXT,
                    arbitration_id INTEGER,
                    hex_id TEXT,
                    message_name TEXT,
                    observed_value TEXT,
                    expected_threshold TEXT,
                    evidence TEXT,
                    mitigation TEXT,
                    raw_frame_hex TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    action TEXT,
                    details TEXT
                )
            """)

    def save_frame(self, frame: CANFrame, bus_load: float = 0.0) -> None:
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO can_frames (timestamp, arbitration_id, hex_id, dlc, data_hex, bus_load_pct) VALUES (?, ?, ?, ?, ?, ?)",
                (frame.timestamp, frame.arbitration_id, frame.hex_id, frame.dlc, frame.hex_data, bus_load)
            )

    def save_batch(self, frames: List[CANFrame], alerts: List[CANAlert], bus_load: float = 0.0) -> None:
        """Buffer one simulation tick; rows are written in one transaction every FLUSH_INTERVAL_S."""
        with self._lock:
            self._buf_frames += [(f.timestamp, f.arbitration_id, f.hex_id, f.dlc, f.hex_data, bus_load) for f in frames]
            self._buf_alerts += [(a.timestamp, a.rule_id, a.rule_name, a.severity, a.arbitration_id, a.hex_id,
                                  a.message_name, str(a.observed_value), str(a.expected_threshold), a.evidence,
                                  a.mitigation, a.raw_frame_hex) for a in alerts]
            self.total_alerts += len(alerts)
            if (time.monotonic() - self._last_flush >= self.FLUSH_INTERVAL_S
                    or len(self._buf_frames) + len(self._buf_alerts) >= self.FLUSH_ROWS):
                self.flush()

    def flush(self) -> None:
        """Write buffered rows and keep every table bounded (frames, alerts and audit are all pruned)."""
        with self._get_conn() as conn:
            if self._buf_frames:
                conn.executemany("INSERT INTO can_frames (timestamp, arbitration_id, hex_id, dlc, data_hex, bus_load_pct) "
                                 "VALUES (?, ?, ?, ?, ?, ?)", self._buf_frames)
            if self._buf_alerts:
                conn.executemany("""INSERT INTO ids_alerts (timestamp, rule_id, rule_name, severity, arbitration_id, hex_id,
                       message_name, observed_value, expected_threshold, evidence, mitigation, raw_frame_hex)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", self._buf_alerts)
            self._writes += len(self._buf_frames) + len(self._buf_alerts)
            self._buf_frames, self._buf_alerts = [], []
            self._last_flush = time.monotonic()
            if self._writes >= min(self.max_frames, self.max_alerts) // 2:
                self._writes = 0
                for table, keep in (("can_frames", self.max_frames), ("ids_alerts", self.max_alerts),
                                    ("audit_log", self.max_audit)):
                    conn.execute(f"DELETE FROM {table} WHERE id <= (SELECT MAX(id) FROM {table}) - ?", (keep,))

    def count_alerts(self) -> int:
        with self._get_conn() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM ids_alerts").fetchone()[0])

    def save_alert(self, alert: CANAlert) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO ids_alerts (
                    timestamp, rule_id, rule_name, severity, arbitration_id, hex_id,
                    message_name, observed_value, expected_threshold, evidence, mitigation, raw_frame_hex
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert.timestamp, alert.rule_id, alert.rule_name, alert.severity,
                    alert.arbitration_id, alert.hex_id, alert.message_name,
                    str(alert.observed_value), str(alert.expected_threshold),
                    alert.evidence, alert.mitigation, alert.raw_frame_hex
                )
            )

    def log_audit(self, action: str, details: Dict[str, Any]) -> None:
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO audit_log (timestamp, action, details) VALUES (?, ?, ?)",
                (time.time(), action, json.dumps(details))
            )

    def get_recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        self.flush()
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ids_alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(row) for row in rows]

    def get_recent_frames(self, limit: int = 100) -> List[Dict[str, Any]]:
        self.flush()
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM can_frames ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(row) for row in rows]

    def export_incident_bundle(self) -> Dict[str, Any]:
        self.flush()
        with self._get_conn() as conn:
            alerts = [dict(r) for r in conn.execute("SELECT * FROM ids_alerts ORDER BY id DESC LIMIT 500").fetchall()]
            frames = [dict(r) for r in conn.execute("SELECT * FROM can_frames ORDER BY id DESC LIMIT 500").fetchall()]
            audit = [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()]
            return {
                "bundle_type": "AUTOMOTIVE_CAN_INCIDENT_BUNDLE",
                "export_time": time.time(),
                "alert_count": len(alerts),
                "frame_sample_count": len(frames),
                "alerts": alerts,
                "frames": frames,
                "audit": audit
            }

    def clear_all(self) -> None:
        with self._lock:
            self._buf_frames, self._buf_alerts = [], []
            self.total_alerts = 0
        with self._get_conn() as conn:
            conn.execute("DELETE FROM ids_alerts")
            conn.execute("DELETE FROM can_frames")
            conn.execute("DELETE FROM audit_log")

    def close(self) -> None:
        try:
            self.flush()
        finally:
            with self._lock:
                self._conn.close()
