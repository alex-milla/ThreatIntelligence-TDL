#!/usr/bin/env bash
#
# ThreatIntelligence-TDL worker updater.
#
# Pulls the latest worker code and refreshes its Python dependencies.
# Untracked files (config.ini, data/, zones/) are never touched.
#
# Usage:
#   bash update.sh              Pull latest code and install dependencies.
#   bash update.sh --restart    Also restart the systemd service (daemon mode).
#   bash update.sh --help       Show this help.
#
# Environment overrides:
#   PYTHON_BIN     Python interpreter (default: python3)
#   SERVICE_NAME   systemd unit name   (default: tdl-worker)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

PYTHON_BIN="${PYTHON_BIN:-python3}"
SERVICE_NAME="${SERVICE_NAME:-tdl-worker}"
RESTART=0

for arg in "$@"; do
    case "${arg}" in
        -r|--restart) RESTART=1 ;;
        -h|--help)
            echo "Usage: bash update.sh [--restart]"
            echo "  (no args)   Pull latest code and install dependencies."
            echo "  --restart   Also restart the systemd service (daemon mode)."
            exit 0
            ;;
        *)
            echo "Unknown option: ${arg}" >&2
            exit 1
            ;;
    esac
done

echo "[*] Repository: ${REPO_DIR}"

if [ ! -d "${REPO_DIR}/.git" ]; then
    echo "[-] ${REPO_DIR} is not a git checkout; cannot auto-update." >&2
    echo "    Redeploy from a release tarball or update manually." >&2
    exit 1
fi

if ! command -v git >/dev/null 2>&1; then
    echo "[-] git is not installed." >&2
    exit 1
fi

echo "[*] Pulling latest code ..."
git -C "${REPO_DIR}" pull --ff-only

echo "[*] Checking worker dependencies ..."
if "${PYTHON_BIN}" -c "import requests" 2>/dev/null; then
    if "${PYTHON_BIN}" -c "import ahocorasick" 2>/dev/null; then
        echo "[+] Python dependencies already available."
    else
        echo "[i] 'requests' present; optional 'pyahocorasick' missing (substring fallback)."
        "${PYTHON_BIN}" -m pip install pyahocorasick >/dev/null 2>&1 || \
            echo "[i] Install it with: apt install python3-ahocorasick (Debian/Ubuntu) if you want the speedup."
    fi
else
    echo "[*] Installing worker dependencies ..."
    if ! "${PYTHON_BIN}" -m pip install -r "${SCRIPT_DIR}/requirements.txt"; then
        echo "[!] Could not install dependencies automatically (PEP 668 externally-managed environment?)." >&2
        echo "    Required: requests. Optional accelerator: pyahocorasick." >&2
        echo "    Debian/Ubuntu:  apt install python3-requests python3-ahocorasick" >&2
        echo "    Or a venv:      python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
        echo "    The worker can still run if 'requests' is already installed." >&2
    fi
fi

NEW_VERSION="$(cat "${REPO_DIR}/VERSION" 2>/dev/null || echo unknown)"
echo "[+] Worker code updated to version ${NEW_VERSION}."

if [ "${RESTART}" -eq 1 ]; then
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "[!] systemctl not found; restart the worker manually." >&2
        exit 0
    fi
    echo "[*] Restarting ${SERVICE_NAME} ..."
    if [ "$(id -u)" -eq 0 ]; then
        systemctl restart "${SERVICE_NAME}"
    else
        sudo systemctl restart "${SERVICE_NAME}"
    fi
    echo "[+] Service ${SERVICE_NAME} restarted."
else
    echo "[i] Cron mode: the next run picks up the new code automatically."
    echo "[i] Daemon mode: re-run with --restart, or: systemctl restart ${SERVICE_NAME}"
fi
