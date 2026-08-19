from __future__ import annotations

import argparse
import ctypes.util
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import shutil
import signal
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from alert_sender import AlertClient
from capture import CaptureManager
from cicflow_runner import CICFlowRunner
from csv_processor import CSVProcessor
from predictor import Predictor
from state import StateStore


class PredictionAgent:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.logger = logging.getLogger("prediction_agent")
        self.running = True
        self._last_alert_retry = 0.0

        self.pcap_dir = Path(config.get("pcap_output_dir", "data/pcaps"))
        self.processed_dir = Path(config.get("processed_dir", "data/processed"))
        self.prediction_dir = self.processed_dir / "predictions"
        self.archive_pcap_dir = self.processed_dir / "pcaps"
        self.archive_csv_dir = self.processed_dir / "csv"

        for directory in (
            self.pcap_dir,
            self.prediction_dir,
            self.archive_pcap_dir,
            self.archive_csv_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

        state_db_path = config.get("state_db_path", self.processed_dir / "state.sqlite")
        self.state = StateStore(db_path=str(state_db_path))
        self.capture = CaptureManager(config, self.logger)
        self.flow_runner = CICFlowRunner(config, self.logger)
        self.csv_processor = CSVProcessor(self.logger)
        self.predictor = Predictor(config.get("model_dir", "model"), self.logger)
        self.alert_client = AlertClient(config, self.logger)

    def stop(self, *_: Any) -> None:
        self.running = False
        self.capture.stop()

    def _completed_pcaps(self, include_newest: bool = False) -> list[Path]:
        files = sorted(
            (path for path in self.pcap_dir.glob("*.pcap*") if path.is_file()),
            key=lambda path: path.stat().st_mtime,
        )
        if not files:
            return []

        # The newest file is assumed to be the file tcpdump is currently writing.
        candidates = files if include_newest else files[:-1]
        if include_newest:
            return candidates

        age_required = float(self.config.get("stability_wait_seconds", 3))
        now = time.time()
        return [path for path in candidates if now - path.stat().st_mtime >= age_required]

    def _archive(self, source: Path, destination_dir: Path) -> Path:
        destination = destination_dir / source.name
        if destination.exists():
            destination = destination_dir / f"{source.stem}_{int(time.time())}{source.suffix}"
        return Path(shutil.move(str(source), str(destination)))

    def _build_alert_payload(self, row: pd.Series, source_csv: Path) -> dict[str, Any]:
        return {
            "event_id": str(uuid.uuid4()),
            "server_name": self.config.get("server_name", "unknown-server"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_csv": source_csv.name,
            "prediction": str(row["Predicted Label"]),
            "predicted_label": str(row["Predicted Label"]),
            "confidence": float(row["Prediction Confidence"]),
            "source_ip": str(row["Src IP"]),
            "source_port": int(row["Src Port"]),
            "destination_ip": str(row["Dst IP"]),
            "flow_duration": float(row["Flow Duration"]),
            "model_version": self.predictor.metadata.get("model_version"),
            "flow": row.to_dict(),
        }

    def retry_queued_alerts(self, force: bool = False) -> tuple[int, int]:
        config = getattr(self, "config", {})
        now = time.time()
        interval = float(config.get("alert_queue_retry_interval_seconds", 60))
        if not force and now - getattr(self, "_last_alert_retry", 0.0) < interval:
            return 0, 0
        self._last_alert_retry = now

        sent = 0
        failed = 0
        batch_size = max(1, int(config.get("alert_queue_retry_batch_size", 10)))
        for queued in self.state.get_queued_alerts()[:batch_size]:
            payload = json.loads(queued["payload"])
            event_id = str(queued["event_id"])
            if self.alert_client.send(payload):
                self.state.remove_alert(event_id)
                sent += 1
            else:
                self.state.update_alert_attempt(event_id, "Alert delivery failed")
                failed += 1

        if sent or failed:
            self.logger.info("Queued alert retry summary: sent=%d failed=%d", sent, failed)
        return sent, failed

    def _predict_csv(self, csv_path: Path) -> bool:
        try:
            incoming = self.csv_processor.read_csv(csv_path)
            if incoming.empty:
                self.logger.warning("No rows to predict in %s", csv_path)
                return True

            results = self.predictor.predict_dataframe(incoming)
            output_name = f"{csv_path.stem}_predictions.csv"
            output_path = self.prediction_dir / output_name
            results.to_csv(output_path, index=False)
            self.logger.info("Saved predictions to %s", output_path)

            minimum_confidence = float(self.config.get("minimum_confidence", 0.8))
            dangerous_labels = list(self.config.get("dangerous_labels", ["MALICIOUS"]))
            print_benign = bool(self.config.get("print_benign", False))

            for _, row in results.iterrows():
                label = str(row["Predicted Label"])
                confidence = float(row["Prediction Confidence"])
                dangerous = self.predictor.is_dangerous_label(label, dangerous_labels)
                confident = self.predictor.meets_confidence_threshold(confidence, minimum_confidence)

                if dangerous and confident:
                    self.logger.warning("Malicious flow detected: label=%s confidence=%.4f", label, confidence)
                    payload = self._build_alert_payload(row, csv_path)
                    if not self.alert_client.send(payload):
                        self.state.queue_alert(payload, "Alert delivery failed")
                        self.logger.error("Queued undelivered alert %s", payload["event_id"])
                elif print_benign:
                    self.logger.info("Flow prediction: label=%s confidence=%.4f", label, confidence)
            return True
        except Exception:
            self.logger.exception("Prediction failed for %s", csv_path)
            return False

    def process_csv(self, csv_path: Path) -> bool:
        csv_key = str(csv_path.resolve())
        if self.state.is_csv_processed(csv_key):
            self.logger.info("Skipping already processed CSV: %s", csv_path)
            return True
        if not csv_path.exists() or not csv_path.is_file():
            self.logger.error("CSV file not found: %s", csv_path)
            return False
        if not self._predict_csv(csv_path):
            return False
        try:
            self._archive(csv_path, self.archive_csv_dir)
        except OSError:
            self.logger.exception("Could not archive CSV %s", csv_path)
            return False
        self.state.mark_csv_processed(csv_key)
        return True

    def process_pcap(self, pcap_path: Path) -> bool:
        pcap_key = str(pcap_path.resolve())
        if self.state.is_pcap_processed(pcap_key):
            self.logger.info("Skipping already processed PCAP: %s", pcap_path)
            return True

        success, error, csv_path = self.flow_runner.run(pcap_path)
        if not success or csv_path is None:
            self.logger.error("Skipping %s: %s", pcap_path, error)
            return False
        if not self._predict_csv(csv_path):
            return False

        csv_key = str(csv_path.resolve())
        try:
            self._archive(csv_path, self.archive_csv_dir)
            self._archive(pcap_path, self.archive_pcap_dir)
        except OSError:
            self.logger.exception("Could not archive processed files for %s", pcap_path)
            return False
        self.state.mark_csv_processed(csv_key)
        self.state.mark_pcap_processed(pcap_key)
        return True

    def run(self) -> None:
        if not self.predictor.is_ready:
            raise RuntimeError("Predictor artifacts are not ready")

        self.retry_queued_alerts(force=True)
        self.logger.info("Starting capture loop on interface %s", self.config.get("interface", "eth0"))
        self.capture.start()
        poll_interval = float(self.config.get("poll_interval_seconds", 5))

        try:
            while self.running:
                if self.capture.process is not None and self.capture.process.poll() is not None:
                    raise RuntimeError(
                        f"tcpdump exited unexpectedly with code {self.capture.process.returncode}"
                    )

                for pcap_file in self._completed_pcaps():
                    self.process_pcap(pcap_file)

                self.retry_queued_alerts()
                time.sleep(poll_interval)
        finally:
            self.capture.stop()
            # Once tcpdump has stopped, its newest file is closed and safe to process.
            for pcap_file in self._completed_pcaps(include_newest=True):
                self.process_pcap(pcap_file)


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    base_dir = config_path.parent
    for key in (
        "pcap_output_dir",
        "csv_output_dir",
        "processed_dir",
        "model_dir",
        "state_db_path",
        "log_dir",
    ):
        value = config.get(key)
        if value and not Path(value).is_absolute():
            config[key] = str((base_dir / value).resolve())
    return config


def configure_logging(
    level_name: str,
    log_dir: str | Path = "logs",
    max_bytes: int = 15 * 1024 * 1024,
    backup_count: int = 5,
) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    file_handler = RotatingFileHandler(
        log_path / "agent.log",
        maxBytes=max(1, int(max_bytes)),
        backupCount=max(1, int(backup_count)),
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)

    logging.basicConfig(
        level=level,
        handlers=[console_handler, file_handler],
        force=True,
    )


def validate_config_values(config: dict[str, Any]) -> list[str]:
    required = [
        "interface",
        "pcap_output_dir",
        "csv_output_dir",
        "processed_dir",
        "model_dir",
        "alert_endpoint_url",
        "cicflow_command",
    ]
    errors = [f"Missing config value: {name}" for name in required if not config.get(name)]

    endpoint = str(config.get("alert_endpoint_url", ""))
    if endpoint and not endpoint.startswith(("http://", "https://")):
        errors.append("alert_endpoint_url must use http:// or https://")

    try:
        confidence = float(config.get("minimum_confidence", 0.8))
        if not 0 <= confidence <= 1:
            errors.append("minimum_confidence must be between 0 and 1")
    except (TypeError, ValueError):
        errors.append("minimum_confidence must be numeric")

    if config.get("cicflow_command") is not None and not isinstance(config.get("cicflow_command"), list):
        errors.append("cicflow_command must be a JSON list")
    return errors


def validate_runtime(config: dict[str, Any], logger: logging.Logger) -> bool:
    errors = validate_config_values(config)
    if not shutil.which("java"):
        errors.append("Java was not found in PATH")
    if not shutil.which("tcpdump"):
        errors.append("tcpdump was not found in PATH")

    if os.name == "nt":
        pcap_available = any(
            path.exists()
            for path in (
                Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "Npcap" / "wpcap.dll",
                Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "wpcap.dll",
            )
        )
        if not pcap_available:
            errors.append("Npcap/WinPcap runtime was not found")
    elif ctypes.util.find_library("pcap") is None:
        errors.append("libpcap was not found")

    interface = str(config.get("interface", ""))
    if os.name != "nt" and interface and not (Path("/sys/class/net") / interface).exists():
        errors.append(f"Network interface was not found: {interface}")

    runner = CICFlowRunner(config, logger)
    try:
        runner._build_command(Path("runtime-check.pcap"), Path(config.get("csv_output_dir", "data/csv")))
    except ValueError as exc:
        errors.append(str(exc))

    predictor = Predictor(config.get("model_dir", "model"), logger)
    if not predictor.is_ready:
        errors.append("Model artifacts could not be loaded")

    for error in errors:
        logger.error("Runtime validation: %s", error)
    if errors:
        return False
    logger.info("Runtime dependencies, interface, CICFlowMeter, and model are ready")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="CICFlowMeter intrusion prediction agent")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    parser.add_argument("--validate-model", action="store_true", help="Validate the model artifacts")
    parser.add_argument("--validate-config", action="store_true", help="Validate the config file")
    parser.add_argument("--validate-runtime", action="store_true", help="Validate host dependencies and artifacts")
    parser.add_argument("--process-pcap", metavar="PCAP", help="Process a single PCAP file")
    parser.add_argument("--process-csv", metavar="CSV", help="Process a single CICFlowMeter CSV file")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="Process all current PCAPs and exit")
    mode.add_argument("--watch", action="store_true", help="Run the continuous capture loop (default)")
    args = parser.parse_args()

    config = load_config(args.config)
    configure_logging(
        str(config.get("log_level", "INFO")),
        config.get("log_dir", "logs"),
        int(config.get("log_max_bytes", 15 * 1024 * 1024)),
        int(config.get("log_backup_count", 5)),
    )

    if args.validate_config:
        errors = validate_config_values(config)
        if errors:
            for error in errors:
                logging.getLogger("prediction_agent").error(error)
            return 1
        logging.getLogger("prediction_agent").info("Configuration looks valid")
        return 0

    if args.validate_runtime:
        logger = logging.getLogger("prediction_agent")
        return 0 if validate_runtime(config, logger) else 1

    if args.validate_model:
        predictor = Predictor(config.get("model_dir", "model"), logging.getLogger("prediction_agent"))
        if predictor.is_ready:
            logging.getLogger("prediction_agent").info("Model artifacts loaded successfully")
            return 0
        logging.getLogger("prediction_agent").error("Model artifacts could not be loaded")
        return 1

    if args.process_pcap:
        pcap_path = Path(args.process_pcap)
        if not pcap_path.exists():
            logging.getLogger("prediction_agent").error("PCAP file not found: %s", pcap_path)
            return 1

        agent = PredictionAgent(config)
        return 0 if agent.process_pcap(pcap_path) else 1

    if args.process_csv:
        csv_path = Path(args.process_csv)
        if not csv_path.exists():
            logging.getLogger("prediction_agent").error("CSV file not found: %s", csv_path)
            return 1
        agent = PredictionAgent(config)
        return 0 if agent.process_csv(csv_path) else 1

    if args.once:
        agent = PredictionAgent(config)
        if not agent.predictor.is_ready:
            logging.getLogger("prediction_agent").error("Predictor artifacts are not ready")
            return 1
        agent.retry_queued_alerts(force=True)
        pcaps = agent._completed_pcaps(include_newest=True)
        if not pcaps:
            logging.getLogger("prediction_agent").info("No PCAP files are ready to process")
            return 0
        results = [agent.process_pcap(path) for path in pcaps]
        return 0 if all(results) else 1

    agent = PredictionAgent(config)
    signal.signal(signal.SIGINT, agent.stop)
    signal.signal(signal.SIGTERM, agent.stop)

    try:
        agent.run()
    except Exception:
        logging.getLogger("prediction_agent").exception("Agent stopped because of a fatal error")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
