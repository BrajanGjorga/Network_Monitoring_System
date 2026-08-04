from __future__ import annotations

import logging
import shlex
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional


class CaptureManager:
    """Manage rotating tcpdump capture files."""

    def __init__(self, config: dict, logger: Optional[logging.Logger] = None) -> None:
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self.process: Optional[subprocess.Popen[str]] = None

    def build_command(self) -> list[str]:
        interface = str(self.config.get("interface", "eth0"))
        output_dir = Path(self.config.get("pcap_output_dir", "data/pcaps"))
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_pattern = str(output_dir / f"capture_{timestamp}_%Y%m%d_%H%M%S.pcap")

        command = [
            "tcpdump",
            "-i",
            interface,
            "-w",
            output_pattern,
            "-G",
            str(int(self.config.get("rotation_seconds", 30))),
            "-W",
            str(int(self.config.get("maximum_capture_files", 100))),
            "-s",
            str(int(self.config.get("snaplen", 0))),
            "-U",
        ]

        capture_filter = self.config.get("capture_filter")
        if capture_filter:
            command.extend(shlex.split(str(capture_filter)))

        return command

    def start(self) -> subprocess.Popen[str]:
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError("tcpdump capture is already running")

        command = self.build_command()
        self.logger.info("Starting tcpdump: %s", shlex.join(command))

        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(f"Unable to start tcpdump: {exc}") from exc
        return self.process

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is not None:
            self.process = None
            return

        self.logger.info("Stopping tcpdump")
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        finally:
            self.process = None
