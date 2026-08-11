import json
import sqlite3
from pathlib import Path
from typing import Optional


class StateStore:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path or "data/state.sqlite")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_schema(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS processed_pcaps (
                    path TEXT PRIMARY KEY,
                    processed_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS processed_csvs (
                    path TEXT PRIMARY KEY,
                    processed_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    error TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def mark_pcap_processed(self, path: str) -> bool:
        conn = self._connect()
        try:
            conn.execute("INSERT INTO processed_pcaps(path, processed_at) VALUES (?, datetime('now'))", (path,))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def mark_csv_processed(self, path: str) -> bool:
        conn = self._connect()
        try:
            conn.execute("INSERT INTO processed_csvs(path, processed_at) VALUES (?, datetime('now'))", (path,))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def is_pcap_processed(self, path: str) -> bool:
        conn = self._connect()
        try:
            row = conn.execute("SELECT 1 FROM processed_pcaps WHERE path = ?", (path,)).fetchone()
            return row is not None
        finally:
            conn.close()

    def is_csv_processed(self, path: str) -> bool:
        conn = self._connect()
        try:
            row = conn.execute("SELECT 1 FROM processed_csvs WHERE path = ?", (path,)).fetchone()
            return row is not None
        finally:
            conn.close()

    def queue_alert(self, payload: dict, error: Optional[str] = None) -> bool:
        event_id = payload.get("event_id")
        if not event_id:
            return False
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO alerts(event_id, payload, created_at, error, attempts) VALUES (?, ?, datetime('now'), ?, 0)",
                (event_id, json.dumps(payload, default=self._json_default), error),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    @staticmethod
    def _json_default(value):
        if hasattr(value, "item"):
            return value.item()
        return str(value)

    def get_queued_alerts(self) -> list[dict]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT event_id, payload, error, attempts FROM alerts ORDER BY created_at").fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def update_alert_attempt(self, event_id: str, error: Optional[str] = None) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE alerts SET attempts = attempts + 1, error = ? WHERE event_id = ?",
                (error, event_id),
            )
            conn.commit()
        finally:
            conn.close()

    def remove_alert(self, event_id: str) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM alerts WHERE event_id = ?", (event_id,))
            conn.commit()
        finally:
            conn.close()

    def get_alert_count(self) -> int:
        conn = self._connect()
        try:
            row = conn.execute("SELECT COUNT(*) AS count FROM alerts").fetchone()
            return int(row["count"])
        finally:
            conn.close()
