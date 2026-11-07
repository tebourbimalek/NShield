#!/usr/bin/env bash
# NShield launcher (Linux / macOS) - re-launches with sudo because ARP
# spoofing requires root privileges.
set -e
cd "$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
    echo "[NShield] Requesting root privileges..."
    exec sudo -- "$0" "$@"
fi

# 1. Python venv + dependencies
if [ ! -x "backend/venv/bin/python" ]; then
    echo "[NShield] Creating Python virtualenv and installing dependencies..."
    python3 -m venv backend/venv
    backend/venv/bin/python -m pip install --upgrade pip
    backend/venv/bin/python -m pip install -r backend/requirements.txt
fi

# 2. Frontend build (served by the Python backend)
if [ ! -f "frontend/dist/index.html" ]; then
    echo "[NShield] Building frontend..."
    ( cd frontend && npm install && npm run build )
fi

# 3. Open the browser once the server is up, then run the backend here
(
    sleep 2
    xdg-open http://127.0.0.1:8000 >/dev/null 2>&1 || open http://127.0.0.1:8000 >/dev/null 2>&1 || true
) &

exec backend/venv/bin/python backend/main.py
