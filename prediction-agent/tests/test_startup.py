import json
import logging
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent import configure_logging, load_config, main
from capture import CaptureManager


class AgentStartupTests(unittest.TestCase):
    def test_relative_paths_are_resolved_from_config_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(
                json.dumps({"model_dir": "model", "log_dir": "logs"}),
                encoding="utf-8",
            )

            loaded = load_config(config_path)

            self.assertEqual(loaded["model_dir"], str((Path(tmpdir) / "model").resolve()))
            self.assertEqual(loaded["log_dir"], str((Path(tmpdir) / "logs").resolve()))

    def test_logging_writes_and_rotates_agent_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                configure_logging("INFO", tmpdir, max_bytes=150, backup_count=2)
                logger = logging.getLogger("prediction_agent")
                for index in range(10):
                    logger.info("Rotating log test entry %d with padding", index)
                for handler in logging.getLogger().handlers:
                    handler.flush()

                log_dir = Path(tmpdir)
                self.assertTrue((log_dir / "agent.log").exists())
                self.assertTrue((log_dir / "agent.log.1").exists())
            finally:
                root_logger = logging.getLogger()
                for handler in root_logger.handlers[:]:
                    root_logger.removeHandler(handler)
                    handler.close()

    def test_validate_config_flag_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config = {
                "interface": "eth0",
                "pcap_output_dir": "data/pcaps",
                "csv_output_dir": "data/csv",
                "processed_dir": "data/processed",
                "model_dir": "model",
                "alert_endpoint_url": "http://127.0.0.1:8001/alerts",
                "cicflow_command": ["java", "-jar", "CICFlowMeter.jar"],
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")

            with patch.object(sys, "argv", ["agent.py", "--config", str(config_path), "--validate-config"]):
                self.assertEqual(main(), 0)

    def test_capture_manager_wraps_missing_tcpdump(self) -> None:
        manager = CaptureManager({})

        with patch("capture.subprocess.Popen", side_effect=FileNotFoundError("tcpdump")):
            with self.assertRaisesRegex(RuntimeError, "Unable to start tcpdump"):
                manager.start()

    def test_process_pcap_flag_dispatches_to_agent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config = {
                "interface": "eth0",
                "pcap_output_dir": "data/pcaps",
                "csv_output_dir": "data/csv",
                "processed_dir": "data/processed",
                "model_dir": "model",
                "alert_endpoint_url": "http://127.0.0.1:8001/alerts",
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")

            pcap_path = Path(tmpdir) / "sample.pcap"
            pcap_path.write_bytes(b"fake-pcap")

            with patch("agent.PredictionAgent.process_pcap") as mock_process_pcap:
                with patch.object(sys, "argv", ["agent.py", "--config", str(config_path), "--process-pcap", str(pcap_path)]):
                    self.assertEqual(main(), 0)

            mock_process_pcap.assert_called_once_with(pcap_path)

    def test_process_pcap_failure_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config = {
                "interface": "eth0",
                "pcap_output_dir": "data/pcaps",
                "csv_output_dir": "data/csv",
                "processed_dir": "data/processed",
                "model_dir": "model",
                "alert_endpoint_url": "http://127.0.0.1:8001/alerts",
                "cicflow_command": ["java", "-jar", "CICFlowMeter.jar"],
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            pcap_path = Path(tmpdir) / "sample.pcap"
            pcap_path.write_bytes(b"fake-pcap")

            with patch("agent.PredictionAgent.process_pcap", return_value=False):
                with patch.object(sys, "argv", ["agent.py", "--config", str(config_path), "--process-pcap", str(pcap_path)]):
                    self.assertEqual(main(), 1)


if __name__ == "__main__":
    unittest.main()
