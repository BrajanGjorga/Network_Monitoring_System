import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from alert_sender import AlertSender
from csv_processor import CSVProcessor
from predictor import Predictor
from state import StateStore


class TestAgentLogic(unittest.TestCase):
    def test_exact_feature_ordering(self):
        processor = CSVProcessor(feature_columns=["a", "b", "c"], metadata={})
        row = {"a": "1", "b": "2", "c": "3"}
        prepared = processor.prepare_row(row)
        self.assertEqual(list(prepared.keys()), ["a", "b", "c"])

    def test_missing_feature_rejection(self):
        processor = CSVProcessor(feature_columns=["a", "b", "c"], metadata={})
        missing = {"a": "1", "b": "2"}
        with self.assertRaises(ValueError):
            processor.prepare_row(missing)

    def test_infinity_handling(self):
        processor = CSVProcessor(feature_columns=["a"], metadata={"infinity_handling_policy": "replace_inf_with_nan"})
        prepared = processor.prepare_row({"a": "inf"})
        self.assertTrue(prepared["a"] is None or prepared["a"] != float("inf"))

    def test_model_loading(self):
        with tempfile.TemporaryDirectory() as tempdir:
            model_path = Path(tempdir)
            (model_path / "model.pkl").write_bytes(b"not-a-real-model")
            (model_path / "scaler.pkl").write_bytes(b"not-a-real-scaler")
            (model_path / "feature_columns.json").write_text(json.dumps(["a", "b"]), encoding="utf-8")
            (model_path / "model_metadata.json").write_text(json.dumps({"feature_count": 2, "mode": "binary", "model_version": "1.0.0"}), encoding="utf-8")
            predictor = Predictor(model_dir=str(model_path))
            self.assertFalse(predictor.is_ready)

    def test_relative_model_path_is_resolved_from_project_root(self):
        predictor = Predictor(model_dir="model")
        self.assertTrue(predictor.is_ready)

    def test_dangerous_label_detection(self):
        self.assertTrue(Predictor.is_dangerous_label("MALICIOUS", ["BENIGN", "MALICIOUS"]))
        self.assertFalse(Predictor.is_dangerous_label("BENIGN", ["BENIGN", "MALICIOUS"]))

    def test_confidence_threshold(self):
        self.assertTrue(Predictor.meets_confidence_threshold(0.95, 0.9))
        self.assertFalse(Predictor.meets_confidence_threshold(0.8, 0.9))

    def test_successful_alert_sending(self):
        sender = AlertSender(endpoint_url="http://example.invalid", timeout=1, max_retries=1)
        self.assertFalse(sender.send_alert({"event_id": "e"}))

    def test_failed_alert_queueing(self):
        with tempfile.TemporaryDirectory() as tempdir:
            db_path = Path(tempdir) / "alerts.sqlite"
            sender = AlertSender(endpoint_url="http://example.invalid", db_path=str(db_path), timeout=1, max_retries=1)
            self.assertTrue(sender.queue_alert({"event_id": "e"}))
            self.assertEqual(sender.get_queued_alert_count(), 1)

    def test_retrying_queued_alerts(self):
        with tempfile.TemporaryDirectory() as tempdir:
            db_path = Path(tempdir) / "alerts.sqlite"
            sender = AlertSender(endpoint_url="http://example.invalid", db_path=str(db_path), timeout=1, max_retries=1)
            sender.queue_alert({"event_id": "e"})
            self.assertEqual(sender.retry_queued_alerts(), 0)

    def test_duplicate_pcap_prevention(self):
        with tempfile.TemporaryDirectory() as tempdir:
            db_path = Path(tempdir) / "state.sqlite"
            store = StateStore(db_path=str(db_path))
            self.assertTrue(store.mark_pcap_processed("foo.pcap"))
            self.assertFalse(store.mark_pcap_processed("foo.pcap"))

    def test_completed_file_detection(self):
        with tempfile.TemporaryDirectory() as tempdir:
            base = Path(tempdir)
            active = base / "active.pcap"
            active.write_bytes(b"abc")
            os.utime(active, (1, 1))
            completed = base / "done.pcap"
            completed.write_bytes(b"abcdef")
            os.utime(completed, (2, 2))
            detected = [p.name for p in sorted(base.glob("*.pcap")) if p.name != "active.pcap"]
            self.assertIn("done.pcap", detected)


if __name__ == "__main__":
    unittest.main()
