#!/usr/bin/env bash
set -e

echo "[*] Installing ThreatIntelligence-TDL Worker ..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$SCRIPT_DIR"

PYTHON_BIN="$(command -v python3 || true)"
if [ -z "${PYTHON_BIN}" ]; then
    echo "[-] python3 not found. Install Python 3.8+ first." >&2
    exit 1
fi

if "${PYTHON_BIN}" -c "import requests, ahocorasick" 2>/dev/null; then
    echo "[+] Python dependencies already available."
else
    if ! "${PYTHON_BIN}" -m pip install -r requirements.txt; then
        echo "[!] Could not install dependencies automatically (PEP 668 externally-managed environment?)." >&2
        echo "    Required: requests. Optional accelerator: pyahocorasick." >&2
        echo "    Debian/Ubuntu:  apt install python3-requests python3-ahocorasick" >&2
        echo "    Or a venv:      python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
    fi
fi

if [ ! -f config.ini ]; then
    cp config.ini.example config.ini
    echo "[+] Created config.ini from example. Please edit it with your credentials."
else
    echo "[!] config.ini already exists. Not overwriting."
fi

mkdir -p zones data

# Install the systemd daemon so the worker can also be updated from the web
# panel (`update_worker` needs git + systemd restart).
SERVICE_NAME="tdl-worker"
if [ -f "${SCRIPT_DIR}/tdl-worker.service" ] && command -v systemctl >/dev/null 2>&1; then
    if [ "$(id -u)" -eq 0 ]; then
        sed \
            -e "s|WorkingDirectory=.*|WorkingDirectory=${SCRIPT_DIR}|" \
            -e "s|ExecStart=.*|ExecStart=${PYTHON_BIN} ${SCRIPT_DIR}/scheduler.py --daemon --interval 60|" \
            "${SCRIPT_DIR}/tdl-worker.service" > "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload
        systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
        echo "[+] systemd service '${SERVICE_NAME}' installed and enabled."
    else
        echo "[i] Not running as root: skipping systemd service installation."
        echo "    Install it manually with sudo if you want daemon mode + panel updates."
    fi
fi

echo "[+] Worker installed."
echo "    Next steps:"
echo "    1. Edit config.ini"
echo "    2. Run once: ${PYTHON_BIN} scheduler.py"
echo "    3. Start the service: systemctl start ${SERVICE_NAME}   (daemon mode)"
echo "       or schedule: ${PYTHON_BIN} ${SCRIPT_DIR}/scheduler.py --once   (cron mode)"
echo "[i] Future updates from the web panel require a git checkout (repo: ${REPO_DIR})."
