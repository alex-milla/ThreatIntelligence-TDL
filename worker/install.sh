#!/usr/bin/env bash
set -e

echo "[*] Installing ThreatIntelligence-TDL Worker ..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

python3 -m pip install -r requirements.txt

if [ ! -f config.ini ]; then
    cp config.ini.example config.ini
    echo "[+] Created config.ini from example. Please edit it with your credentials."
else
    echo "[!] config.ini already exists. Not overwriting."
fi

mkdir -p zones data

echo "[+] Worker installed."
echo "    Next steps:"
echo "    1. Edit config.ini"
echo "    2. Run: python3 scheduler.py"
