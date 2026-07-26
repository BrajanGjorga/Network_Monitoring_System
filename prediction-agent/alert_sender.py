import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import requests

from state import StateStore


class AlertSender:
    def __init__(self, endpoint_url: str, db_path: Optional[str] = None, timeout: int = 3, max_retries: int = 3, backoff_seconds: float = 1.0, logger: Optional[logging.Logger] = None):
        self.endpoint_url = endpoint_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.logger = logger or logging.getLogger(__name__)
        self.state = StateStore(db_path=db_path or "data/alerts.sqlite")

    def build_payload(self, prediction: str, confidence: float, metadata: dict, model_version: str) -> dict:
        payload = {
            "event_id": str(uuid.uuid4()),
            "server_name": metadata.get("server_name", "monitored-server-1"),
            "timestamp": metadata.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
            "prediction": prediction,
            "confidence": confidence,
            "source_ip": metadata.get("source_ip"),
            "destination_ip": metadata.get("destination_ip"),
            "source_port": metadata.get("source_port"),
            "destination_port": metadata.get("destination_port"),
            "protocol": metadata.get("protocol"),
            "flow_duration": metadata.get("flow_duration"),
            "model_version": model_version,
        }
        return payload

    def send_alert(self, payload: dict) -> bool:
        try:
            response = requests.post(self.endpoint_url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            self.logger.info("Alert sent: %s", payload.get("event_id"))
            return True
        except requests.RequestException as exc:
            self.logger.warning("Alert send failed for %s: %s", payload.get("event_id"), exc)
            return False

    def queue_alert(self, payload: dict) -> bool:
        return self.state.queue_alert(payload)

    def get_queued_alert_count(self) -> int:
        return self.state.get_alert_count()

    def retry_queued_alerts(self) -> int:
        queued = self.state.get_queued_alerts()
        sent = 0
        for row in queued:
            payload = row.get("payload")
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except json.JSONDecodeError:
                    payload = {"event_id": row.get("event_id")}
            if self.send_alert(payload):
                self.state.remove_alert(payload["event_id"])
                sent += 1
            else:
                self.state.update_alert_attempt(payload["event_id"], error="send_failed")
                time.sleep(self.backoff_seconds)
        return sent
