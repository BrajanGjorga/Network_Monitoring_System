import logging
import subprocess
from pathlib import Path
from typing import Optional


class CICFlowRunner:
    def __init__(self, config: dict, logger: Optional[logging.Logger] = None):
        self.config = config
        self.logger = logger or logging.getLogger(__name__)

    def run(self, pcap_path: str) -> tuple[bool, Optional[str], Optional[Path]]:
        pcap_file = Path(pcap_path)
        if not pcap_file.exists():
            self.logger.error("PCAP file not found: %s", pcap_file)
            return False, "PCAP file not found", None

        command = list(self.config.get("cicflow_command", ["java", "-jar", "CICFlowMeter.jar"]))
        if not command:
            self.logger.error("CICFlowMeter command is not configured")
            return False, "CICFlowMeter command is not configured", None

        output_dir = Path(self.config.get("csv_output_dir", "data/csv"))
        output_dir.mkdir(parents=True, exist_ok=True)
        output_csv = output_dir / f"{pcap_file.stem}.csv"

        command = command + [str(pcap_file), "-o", str(output_dir)]
        self.logger.info("Running CICFlowMeter for %s", pcap_file)
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=self.config.get("http_timeout_seconds", 10))
        except subprocess.TimeoutExpired as exc:
            self.logger.error("CICFlowMeter timed out for %s", pcap_file)
            return False, str(exc), None

        if completed.returncode != 0:
            self.logger.error("CICFlowMeter failed for %s: %s", pcap_file, completed.stderr.strip())
            return False, completed.stderr.strip(), None

        if not output_csv.exists():
            self.logger.error("Expected CSV output was not created: %s", output_csv)
            return False, "Expected CSV output was not created", None

        self.logger.info("CICFlowMeter created %s", output_csv)
        return True, None, output_csv
