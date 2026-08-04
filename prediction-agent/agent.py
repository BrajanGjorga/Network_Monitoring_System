from __future__ import annotations

import argparse
import json
import logging
import shutil
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from alert_sender import AlertClient
from capture import CaptureManager
from cicflow_runner import CICFlowRunner
from csv_processor import CSVProcessor
from predictor import Predictor


class PredictionAgent:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.logger = logging.getLogger("prediction_agent")
        self.capture = CaptureManager(config, self.logger)
        self.flow_runner = CICFlowRunner(config, self.logger)
        self.csv_processor = CSVProcessor(self.logger)
        self.predictor = Predictor(config.get("model_dir", "model"), self.logger)
        self.alert_client = AlertClient(config, self.logger)
        self.running = True

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

    def stop(self, *_: Any) -> None:
        self.running = False
        self.capture.stop()

    def _completed_pcaps(self) -> list[Path]:
        files = sorted(
            (path for path in self.pcap_dir.glob("*.pcap") if path.is_file()),
            key=lambda path: path.stat().st_mtime,
        )
        if len(files) <= 1:
            return []

        # The newest file is assumed to be the file tcpdump is currently writing.
        candidates = files[:-1]
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
            "server_name": self.config.get("server_name", "unknown-server"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_csv": source_csv.name,
            "predicted_label": str(row["Predicted Label"]),
            "confidence": float(row["Prediction Confidence"]),
            "flow": row.to_dict(),
        }

    def process_pcap(self, pcap_path: Path) -> None:
        success, error, csv_path = self.flow_runner.run(pcap_path)
        if not success or csv_path is None:
            self.logger.error("Skipping %s: %s", pcap_path, error)
            return

        try:
            incoming = self.csv_processor.read_csv(csv_path)
            if incoming.empty:
                self.logger.warning("No rows to predict in %s", csv_path)
                self._archive(csv_path, self.archive_csv_dir)
                self._archive(pcap_path, self.archive_pcap_dir)
                return

            results = self.predictor.predict_dataframe(incoming)
        except Exception:
            self.logger.exception("Prediction failed for %s", csv_path)
            return

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
                self.alert_client.send(self._build_alert_payload(row, csv_path))
            elif print_benign:
                self.logger.info("Flow prediction: label=%s confidence=%.4f", label, confidence)

        self._archive(csv_path, self.archive_csv_dir)
        self._archive(pcap_path, self.archive_pcap_dir)

    def run(self) -> None:
        if not self.predictor.is_ready:
            raise RuntimeError("Predictor artifacts are not ready")

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

                time.sleep(poll_interval)
        finally:
            self.capture.stop()


def load_config(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def configure_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="CICFlowMeter intrusion prediction agent")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    parser.add_argument("--validate-model", action="store_true", help="Validate the model artifacts")
    parser.add_argument("--validate-config", action="store_true", help="Validate the config file")
    args = parser.parse_args()

    config = load_config(args.config)
    configure_logging(str(config.get("log_level", "INFO")))

    if args.validate_config:
        required = ["interface", "pcap_output_dir", "csv_output_dir", "processed_dir", "model_dir", "alert_endpoint_url"]
        missing = [name for name in required if not config.get(name)]
        if missing:
            logging.getLogger("prediction_agent").error("Missing config values: %s", ", ".join(missing))
            return 1
        logging.getLogger("prediction_agent").info("Configuration looks valid")
        return 0

    if args.validate_model:
        predictor = Predictor(config.get("model_dir", "model"), logging.getLogger("prediction_agent"))
        if predictor.is_ready:
            logging.getLogger("prediction_agent").info("Model artifacts loaded successfully")
            return 0
        logging.getLogger("prediction_agent").error("Model artifacts could not be loaded")
        return 1

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
