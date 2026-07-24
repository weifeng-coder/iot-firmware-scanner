#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 web_ui.py --host 127.0.0.1 --port 8088
