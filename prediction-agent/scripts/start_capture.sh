#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
INTERFACE="${1:-eth0}"
OUTPUT_DIR="$ROOT_DIR/data/pcaps"
mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_PATTERN="$OUTPUT_DIR/capture_${TIMESTAMP}_%Y%m%d_%H%M%S.pcap"

# Example command. Replace with the interface name you want to monitor.
exec tcpdump -i "$INTERFACE" -w "$OUTPUT_PATTERN" -G 30 -W 100 -s 96
