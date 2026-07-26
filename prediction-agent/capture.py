import logging
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class CaptureManager:
    def __init__(self, config: dict, logger: Optional[logging.Logger] = None):
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self.process: Optional[subprocess.Popen] = None

    def build_command(self) -> list[str]:
        interface = self.config.get("interface", "eth0")
        output_dir = Path(self.config.get("pcap_output_dir", "data/pcaps"))
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_pattern = str(output_dir / f"capture_{timestamp}_%Y%m%d_%H%M%S.pcap")
        return [
            "tcpdump",
            "-i",
            interface,
            "-w",
            output_pattern,
            "-G",
            str(self.config.get("rotation_seconds", 30)),
            "-W",
            "100",
            "-s",
            "96",
        ]

    def start(self) -> subprocess.Popen:
        command = self.build_command()
        self.logger.info("Starting tcpdump capture with command: %s", shlex.join(command))
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return self.process

    def stop(self) -> None:
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.process = None
