# Contributing to NShield

Thanks for helping out. NShield touches people's networks, so a few ground
rules matter more than usual here.

## Before you start

- NShield is **Windows-first** today. Speed caps (QoS) and the autostart
  task are Windows-only; the ARP engine and the web UI work anywhere Python
  + scapy run. If you are adding a feature, decide which side of that line
  it lives on and document it.
- Read the legal warning in `README.md`. Never add features whose only use
  is to attack networks the user does not own.

## Development setup

```bash
python -m venv backend/venv
backend/venv/Scripts/pip install -r backend/requirements.txt   # Windows
backend/venv/bin/pip install -r backend/requirements.txt       # Linux/macOS
cd frontend && npm install && npm run build && cd ..
backend/venv/Scripts/python backend/main.py                   # run as Administrator
```

For UI work: keep the backend running and `npm run dev` in `frontend/` (Vite
proxies `/api` to port 8000).

## Tests

```bash
cd backend && python -m pytest
```

Tests use an in-memory fake state; do not require network or admin rights.
Add a test for every behaviour change in `backend/main.py`.

## Style

- Python: follow the existing style (type hints where useful, logging over
  print). Keep `main.py`'s public helpers documented.
- Frontend: React + Tailwind, no technical jargon in user-facing copy. The
  UI speaks in plain words ("Cut off", "Watching", "Protecting").
- One concern per PR. Small PRs get reviewed fast.

## Pull requests

1. Fork and create a feature branch.
2. Run the tests and `npm run build`.
3. Open a PR describing *what* changed and *why*, plus how you tested it.
4. Be patient — this is a hobby project.

## Reporting bugs

Use the issue templates. Include your OS, Python version, and the tail of
`backend/logs/nshield.log` (it contains no secrets beyond local IPs).
