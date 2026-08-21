from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class AlertClient:
    API_TOKEN_ENV = "PREDICTION_AGENT_API_TOKEN"

    def __init__(self, config: dict, logger: Optional[logging.Logger] = None) -> None:
        self.config = config
        self.logger = logger or logging.getLogger(__name__)

    @staticmethod
    def _json_default(value: Any) -> Any:
        if hasattr(value, "item"):
            return value.item()
        return str(value)

    def send(self, payload: dict[str, Any]) -> bool:
        endpoint = str(self.config.get("alert_endpoint_url", "")).strip()
        if not endpoint:
            self.logger.warning("No alert_endpoint_url configured; alert not sent")
            return False

        auth_token = os.environ.get(self.API_TOKEN_ENV, "").strip()
        if not auth_token:
            self.logger.error(
                "Missing required %s environment variable; alert not sent",
                self.API_TOKEN_ENV,
            )
            return False

        body = json.dumps(payload, default=self._json_default).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {auth_token}",
        }
        request = Request(
            endpoint,
            data=body,
            headers=headers,
            method="POST",
        )

        attempts = max(1, int(self.config.get("retry_count", 3)))
        backoff = float(self.config.get("retry_backoff_seconds", 1.0))
        timeout = float(self.config.get("http_timeout_seconds", 3))

        for attempt in range(1, attempts + 1):
            try:
                with urlopen(request, timeout=timeout) as response:
                    if 200 <= response.status < 300:
                        return True
                    self.logger.error("Alert endpoint returned status %s", response.status)
            except (HTTPError, URLError, TimeoutError) as exc:
                self.logger.warning("Alert attempt %d/%d failed: %s", attempt, attempts, exc)

            if attempt < attempts:
                time.sleep(backoff * attempt)

        return False
