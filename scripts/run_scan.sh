#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:?usage: scripts/run_scan.sh <firmware-file-or-root-dir>}"
cd "$(dirname "$0")/.."
python3 firmware_scanner.py "$TARGET" -o outputs/result.json --html outputs/report.html --markdown outputs/report.md
