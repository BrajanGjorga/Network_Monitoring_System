from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Optional


class CICFlowRunner:
    """Run the configured CICFlowMeter command for one completed PCAP."""

    def __init__(self, config: dict, logger: Optional[logging.Logger] = None) -> None:
        self.config = config
        self.logger = logger or logging.getLogger(__name__)

    def _build_command(self, pcap_file: Path, output_dir: Path) -> list[str]:
        configured = self.config.get("cicflow_command")
        if not configured or not isinstance(configured, list):
            raise ValueError("cicflow_command must be a non-empty JSON list")

        command = [
            str(part)
            .replace("{pcap}", str(pcap_file.resolve()))
            .replace("{output_dir}", str(output_dir.resolve()))
            for part in configured
        ]

        # Backward compatibility with a base command that has no placeholders.
        joined = " ".join(str(part) for part in configured)
        if "{pcap}" not in joined and "{output_dir}" not in joined:
            command.extend([str(pcap_file.resolve()), "-o", str(output_dir.resolve())])

        return command

    def run(self, pcap_path: str | Path) -> tuple[bool, Optional[str], Optional[Path]]:
        pcap_file = Path(pcap_path)
        if not pcap_file.exists():
            message = f"PCAP file not found: {pcap_file}"
            self.logger.error(message)
            return False, message, None
        if pcap_file.stat().st_size == 0:
            message = f"PCAP file is empty: {pcap_file}"
            self.logger.error(message)
            return False, message, None

        output_dir = Path(self.config.get("csv_output_dir", "data/csv"))
        output_dir.mkdir(parents=True, exist_ok=True)

        before = {path.resolve() for path in output_dir.rglob("*.csv")}

        try:
            command = self._build_command(pcap_file, output_dir)
        except ValueError as exc:
            self.logger.error("Invalid CICFlowMeter configuration: %s", exc)
            return False, str(exc), None

        self.logger.info("Running CICFlowMeter: %s", command)

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=float(self.config.get("cicflow_timeout_seconds", 300)),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            message = f"CICFlowMeter timed out for {pcap_file}: {exc}"
            self.logger.error(message)
            return False, message, None
        except OSError as exc:
            message = f"Could not start CICFlowMeter: {exc}"
            self.logger.error(message)
            return False, message, None

        if completed.returncode != 0:
            details = completed.stderr.strip() or completed.stdout.strip() or "No error output"
            message = f"CICFlowMeter failed with code {completed.returncode}: {details}"
            self.logger.error(message)
            return False, message, None

        after = {path.resolve() for path in output_dir.rglob("*.csv")}
        new_files = [Path(path) for path in after - before]

        if not new_files:
            expected = output_dir / f"{pcap_file.stem}.csv"
            if expected.exists():
                new_files = [expected]

        if not new_files:
            message = f"CICFlowMeter completed but no new CSV was found in {output_dir}"
            self.logger.error(message)
            if completed.stdout.strip():
                self.logger.info("CICFlowMeter stdout: %s", completed.stdout.strip())
            return False, message, None

        output_csv = max(new_files, key=lambda path: path.stat().st_mtime)
        self.logger.info("CICFlowMeter created %s", output_csv)
        return True, None, output_csv
