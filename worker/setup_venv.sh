#!/usr/bin/env bash
#
# Create a virtualenv for the TDL worker.
#
# Debian/Ubuntu mark the system Python as "externally managed" (PEP 668) and
# refuse system-wide pip installs. This creates worker/.venv with the required
# dependencies (including pyarrow for the OpenINTEL ccTLD importer).
#
# After running it, re-run install.sh / update.sh so the systemd units use the
# virtualenv Python.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    echo "[-] ${PYTHON_BIN} not found. Install Python 3.8+ first." >&2
    exit 1
fi

if ! "${PYTHON_BIN}" -m venv "${VENV_DIR}"; then
    echo "[-] Could not create the virtualenv. Install the venv support first:" >&2
    echo "      sudo apt install python3-venv python3-full" >&2
    exit 1
fi

echo "[*] Upgrading pip ..."
"${VENV_DIR}/bin/python" -m pip install --upgrade pip >/dev/null

echo "[*] Installing requirements ..."
"${VENV_DIR}/bin/pip" install -r "${SCRIPT_DIR}/requirements.txt"

echo "[+] Virtualenv ready: ${VENV_DIR}"
echo "    Next: bash ${SCRIPT_DIR}/install.sh"
echo "    The systemd units will be pointed at ${VENV_DIR}/bin/python."
