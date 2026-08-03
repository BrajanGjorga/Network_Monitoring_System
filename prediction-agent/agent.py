import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent

from alert_sender import AlertSender
from capture import CaptureManager
from cicflow_runner import CICFlowRunner
from csv_processor import CSVProcessor
from predictor import Predictor
from state import StateStore


def resolve_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return (PROJECT_ROOT / candidate).resolve()


def load_config(path: str) -> dict:
    config_path = resolve_path(path)
    with config_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def configure_logging(level: str) -> logging.Logger:
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(message)s")
    return logging.getLogger("prediction-agent")


def process_pcap_file(pcap_path: str, config: dict, logger: logging.Logger, state: StateStore, predictor: Predictor, alert_sender: AlertSender) -> bool:
    if state.is_pcap_processed(pcap_path):
        logger.info("Skipping already processed PCAP: %s", pcap_path)
        return True

    runner = CICFlowRunner(config=config, logger=logger)
    success, error, csv_path = runner.run(pcap_path)
    if not success or csv_path is None:
        logger.error("Failed to process PCAP %s: %s", pcap_path, error)
        return False

    feature_columns = predictor.feature_columns
    metadata = predictor.metadata
    processor = CSVProcessor(feature_columns=feature_columns, metadata=metadata, logger=logger)
    rows = processor.process_csv(str(csv_path))
    logger.info("Processed CSV %s with %d rows", csv_path, len(rows))

    dangerous_count = 0
    benign_count = 0
    sent_count = 0
    invalid_count = 0
    for row in rows:
        try:
            prepared = processor.prepare_row(row)
        except ValueError as exc:
            invalid_count += 1
            logger.warning("Rejected incompatible row: %s", exc)
            continue
        label, confidence = predictor.predict(prepared)
        if predictor.is_dangerous_label(label, config.get("dangerous_labels", [])) and predictor.meets_confidence_threshold(confidence, config.get("minimum_confidence", 0.8)):
            dangerous_count += 1
            payload = alert_sender.build_payload(label, confidence, {"server_name": config.get("server_name", "monitored-server-1"), "source_ip": row.get("Source IP") or None, "destination_ip": row.get("Destination IP") or None, "source_port": row.get("Src Port") or None, "destination_port": row.get("Dst Port") or None, "protocol": row.get("Protocol") or None, "flow_duration": row.get("Flow Duration") or None}, predictor.metadata.get("model_version", "unknown"))
            if alert_sender.send_alert(payload):
                sent_count += 1
            else:
                alert_sender.queue_alert(payload)
        else:
            benign_count += 1
            if config.get("print_benign", False):
                logger.info("Benign prediction: %s", label)

    logger.info("Predictions: benign=%d dangerous=%d invalid=%d sent=%d", benign_count, dangerous_count, invalid_count, sent_count)
    state.mark_pcap_processed(pcap_path)
    state.mark_csv_processed(str(csv_path))
    return True


def validate_model(config: dict, logger: logging.Logger) -> bool:
    model_dir = resolve_path(config.get("model_dir", "model"))
    predictor = Predictor(model_dir=str(model_dir), logger=logger)
    return predictor.validate()


def validate_config(config: dict, logger: logging.Logger) -> bool:
    required_keys = ["interface", "pcap_output_dir", "csv_output_dir", "processed_dir", "model_dir", "alert_endpoint_url", "dangerous_labels", "minimum_confidence"]
    missing = [key for key in required_keys if key not in config]
    if missing:
        logger.error("Missing config keys: %s", ", ".join(missing))
        return False
    logger.info("Configuration is valid")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple network-flow prediction agent")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--validate-model", action="store_true")
    parser.add_argument("--validate-config", action="store_true")
    parser.add_argument("--process-pcap", dest="process_pcap", help="Process one existing PCAP file")
    parser.add_argument("--process-csv", dest="process_csv", help="Process one existing CSV file")
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    config = load_config(args.config)
    logger = configure_logging(config.get("log_level", "INFO"))
    logger.info("Loaded configuration from %s", resolve_path(args.config))

    if args.validate_config:
        sys.exit(0 if validate_config(config, logger) else 1)
    if args.validate_model:
        sys.exit(0 if validate_model(config, logger) else 1)

    predictor = Predictor(model_dir=str(resolve_path(config.get("model_dir", "model"))), logger=logger)
    if not predictor.validate():
        logger.error("Model artifacts could not be validated")
        sys.exit(1)

    alert_sender = AlertSender(endpoint_url=config.get("alert_endpoint_url", "http://127.0.0.1:8001/alerts"), db_path=str(resolve_path("data/alerts.sqlite")), timeout=config.get("http_timeout_seconds", 3), max_retries=config.get("retry_count", 3), backoff_seconds=config.get("retry_backoff_seconds", 1.0), logger=logger)
    state = StateStore(db_path=str(resolve_path("data/state.sqlite")))

    if args.process_pcap:
        process_pcap_file(args.process_pcap, config, logger, state, predictor, alert_sender)
        return
    if args.process_csv:
        csv_path = Path(args.process_csv)
        processor = CSVProcessor(feature_columns=predictor.feature_columns, metadata=predictor.metadata, logger=logger)
        rows = processor.process_csv(str(csv_path))
        logger.info("Processed CSV %s with %d rows", csv_path, len(rows))
        return

    while True:
        pcap_dir = resolve_path(config.get("pcap_output_dir", "data/pcaps"))
        completed_pcaps = []
        for pcap_path in pcap_dir.glob("*.pcap"):
            if not state.is_pcap_processed(str(pcap_path)):
                completed_pcaps.append(str(pcap_path))
        logger.info("Found %d completed PCAP files", len(completed_pcaps))
        for pcap_path in completed_pcaps:
            process_pcap_file(pcap_path, config, logger, state, predictor, alert_sender)
        alert_sender.retry_queued_alerts()
        if args.once or not args.watch:
            break
        time.sleep(config.get("poll_interval_seconds", 5))


if __name__ == "__main__":
    main()
