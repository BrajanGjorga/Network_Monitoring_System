import json
import os
import sqlite3
import sys
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from alert_sender import AlertClient
from agent import PredictionAgent
from cicflow_runner import CICFlowRunner
from capture import CaptureManager
from csv_processor import CSVProcessor
from predictor import Predictor
from state import StateStore


class TestAgentLogic(unittest.TestCase):
    def test_exact_feature_ordering(self):
        dataframe = pd.DataFrame([{"a": "1", "b": "2", "c": "3"}])
        prepared = Predictor.prepare_feature_frame_static(dataframe, ["a", "b", "c"])
        self.assertEqual(list(prepared.columns), ["a", "b", "c"])

    def test_cicflowmeter_4_columns_are_mapped_to_training_schema(self):
        cicflow_header = (
            "Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,Flow Duration,"
            "Total Fwd Packet,Total Bwd packets,Total Length of Fwd Packet,"
            "Total Length of Bwd Packet,Fwd Packet Length Max,Fwd Packet Length Min,"
            "Fwd Packet Length Mean,Fwd Packet Length Std,Bwd Packet Length Max,"
            "Bwd Packet Length Min,Bwd Packet Length Mean,Bwd Packet Length Std,"
            "Flow Bytes/s,Flow Packets/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,"
            "Flow IAT Min,Fwd IAT Total,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,"
            "Fwd IAT Min,Bwd IAT Total,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,"
            "Bwd IAT Min,Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,"
            "Fwd Header Length,Bwd Header Length,Fwd Packets/s,Bwd Packets/s,"
            "Packet Length Min,Packet Length Max,Packet Length Mean,Packet Length Std,"
            "Packet Length Variance,FIN Flag Count,SYN Flag Count,RST Flag Count,"
            "PSH Flag Count,ACK Flag Count,URG Flag Count,CWR Flag Count,ECE Flag Count,"
            "Down/Up Ratio,Average Packet Size,Fwd Segment Size Avg,Bwd Segment Size Avg,"
            "Fwd Bytes/Bulk Avg,Fwd Packet/Bulk Avg,Fwd Bulk Rate Avg,Bwd Bytes/Bulk Avg,"
            "Bwd Packet/Bulk Avg,Bwd Bulk Rate Avg,Subflow Fwd Packets,Subflow Fwd Bytes,"
            "Subflow Bwd Packets,Subflow Bwd Bytes,FWD Init Win Bytes,Bwd Init Win Bytes,"
            "Fwd Act Data Pkts,Fwd Seg Size Min,Active Mean,Active Std,Active Max,"
            "Active Min,Idle Mean,Idle Std,Idle Max,Idle Min,Label"
        ).split(",")
        feature_columns = json.loads(
            (ROOT / "model" / "feature_columns.json").read_text(encoding="utf-8")
        )
        dataframe = pd.DataFrame([range(len(cicflow_header))], columns=cicflow_header)

        prepared = Predictor.prepare_feature_frame_static(dataframe, feature_columns)

        self.assertEqual(list(prepared.columns), feature_columns)
        self.assertEqual(prepared.iloc[0].tolist(), [4, 5, *range(7, 83)])

    def test_cicflowmeter_mapping_is_case_insensitive(self):
        dataframe = pd.DataFrame([{"flow duration": "123"}])
        prepared = Predictor.prepare_feature_frame_static(dataframe, ["Flow Duration"])
        self.assertEqual(prepared.loc[0, "Flow Duration"], 123)

    def test_missing_feature_rejection(self):
        dataframe = pd.DataFrame([{"a": "1", "b": "2"}])
        with self.assertRaises(ValueError):
            Predictor.prepare_feature_frame_static(dataframe, ["a", "b", "c"])

    def test_infinity_handling(self):
        dataframe = pd.DataFrame([{"a": "inf"}])
        prepared = Predictor.prepare_feature_frame_static(dataframe, ["a"])
        self.assertTrue(pd.isna(prepared.iloc[0, 0]))

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
        predictor = Predictor(model_dir="model")
        self.assertTrue(predictor.is_dangerous_label("MALICIOUS", ["BENIGN", "MALICIOUS"]))
        self.assertFalse(predictor.is_dangerous_label("BENIGN", ["BENIGN", "MALICIOUS"]))

    def test_confidence_threshold(self):
        self.assertTrue(Predictor.meets_confidence_threshold(0.95, 0.9))
        self.assertFalse(Predictor.meets_confidence_threshold(0.8, 0.9))

    def test_failed_alert_sending_returns_false(self):
        sender = AlertClient({"alert_endpoint_url": "http://example.invalid", "retry_count": 1, "retry_backoff_seconds": 0, "http_timeout_seconds": 1})
        with patch("alert_sender.urlopen", side_effect=URLError("offline")):
            self.assertFalse(sender.send({"event_id": "e"}))

    def test_alert_sender_uses_bearer_token_from_environment(self):
        sender = AlertClient({"alert_endpoint_url": "https://alerts.example/api", "retry_count": 1})
        response_context = MagicMock()
        response_context.__enter__.return_value.status = 202
        with patch.dict(os.environ, {"PREDICTION_AGENT_ALERT_TOKEN": "secret"}):
            with patch("alert_sender.urlopen", return_value=response_context) as mock_urlopen:
                self.assertTrue(sender.send({"event_id": "e"}))

        request = mock_urlopen.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer secret")

    def test_duplicate_pcap_prevention(self):
        with tempfile.TemporaryDirectory() as tempdir:
            db_path = Path(tempdir) / "state.sqlite"
            store = StateStore(db_path=str(db_path))
            self.assertTrue(store.mark_pcap_processed("foo.pcap"))
            self.assertFalse(store.mark_pcap_processed("foo.pcap"))

    def test_default_cicflow_command_uses_bundled_launcher(self):
        runner = CICFlowRunner({"cicflow_command": ["java", "-jar", "CICFlowMeter.jar"]})
        command = runner._build_command(Path("data/pcaps/sample.pcap"), Path("data/csv"))

        self.assertEqual(command[0], "cmd")
        self.assertEqual(command[1], "/c")
        self.assertIn("cfm.bat", command[2])
        self.assertEqual(command[3], str((Path("data/pcaps/sample.pcap")).resolve()))
        self.assertEqual(command[4], str((Path("data/csv")).resolve()))
        self.assertEqual(runner._bundled_launcher_dir().name, "bin")

    def test_custom_cicflow_command_does_not_require_bundled_tool(self):
        runner = CICFlowRunner(
            {"cicflow_command": ["custom-cfm", "{pcap}", "{output_dir}"]}
        )
        with tempfile.TemporaryDirectory() as tempdir:
            runner._resolve_project_root = lambda: Path(tempdir) / "missing-project"
            command = runner._build_command(Path("sample.pcap"), Path("csv"))

        self.assertEqual(command[0], "custom-cfm")
        self.assertEqual(command[1], str(Path("sample.pcap").resolve()))
        self.assertEqual(command[2], str(Path("csv").resolve()))

    def test_capture_command_enforces_size_rotation(self):
        manager = CaptureManager({"max_pcap_size_mb": 25})
        command = manager.build_command()
        self.assertEqual(command[command.index("-C") + 1], "25")
        self.assertNotIn("-W", command)

    def test_alert_payload_matches_receiver_contract(self):
        from test_receiver import AlertPayload

        agent = PredictionAgent.__new__(PredictionAgent)
        agent.config = {"server_name": "test-server"}
        agent.predictor = SimpleNamespace(metadata={"model_version": "1.2.3"})
        row = pd.Series({"Predicted Label": "MALICIOUS", "Prediction Confidence": 0.99})

        payload = agent._build_alert_payload(row, Path("flows.csv"))
        validated = AlertPayload(**payload)

        self.assertTrue(validated.event_id)
        self.assertEqual(validated.prediction, "MALICIOUS")
        self.assertEqual(validated.model_version, "1.2.3")

    def test_queued_alerts_are_retried_and_removed(self):
        with tempfile.TemporaryDirectory() as tempdir:
            agent = PredictionAgent.__new__(PredictionAgent)
            agent.state = StateStore(db_path=str(Path(tempdir) / "state.sqlite"))
            agent.alert_client = MagicMock()
            agent.alert_client.send.return_value = True
            agent.logger = MagicMock()
            self.assertTrue(agent.state.queue_alert({"event_id": "e-1", "value": np.int64(4)}))

            self.assertEqual(agent.retry_queued_alerts(), (1, 0))
            self.assertEqual(agent.state.get_alert_count(), 0)

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

    def test_final_single_pcap_is_detected_after_capture_stops(self):
        with tempfile.TemporaryDirectory() as tempdir:
            agent = PredictionAgent.__new__(PredictionAgent)
            agent.pcap_dir = Path(tempdir)
            agent.config = {"stability_wait_seconds": 3}
            final_capture = agent.pcap_dir / "capture.pcap"
            final_capture.write_bytes(b"pcap")

            self.assertEqual(agent._completed_pcaps(), [])
            self.assertEqual(agent._completed_pcaps(include_newest=True), [final_capture])


if __name__ == "__main__":
    unittest.main()
