# NetGuard

A modern network device controller for **your own home lab**. NetGuard discovers
every device on your subnet (ARP scan), lets you watch them go online/offline live
over a WebSocket, and — with one toggle per device — performs two-way ARP
spoofing (NetCut-style isolation) to cut that device's traffic to the gateway.
Turning the device toggle (or the master switch) off sends restoration packets
that fix every touched ARP cache.

**Stack:** Python 3.11+ / Scapy / FastAPI (REST + WebSocket) · React + Vite +
TailwindCSS (dark UI, Lucide icons) · the Python process serves the built
frontend, so the whole app is one local URL.

> **Platform note:** NetGuard is **Windows-first**. Device blocking (ARP/NDP
> spoofing) and the web UI work on Linux/macOS too, but speed caps (Windows
> QoS), the autostart task and the notification balloons are Windows-only.
> See the cross-platform roadmap in `CONTRIBUTING.md`.

---

## ⚠️ Legal & ethical warning

ARP spoofing cuts traffic of devices on a network you **do not own** just as
easily as on your own. Using NetGuard on networks without explicit authorization
(school, work, hotel, your landlord's Wi-Fi…) may be **illegal** (e.g. computer
fraud / misuse laws) and is always a serious breach of trust that can disrupt
other people's connectivity.

> **Only use on networks you own or have written permission to manage.
> Unauthorized use may be illegal in your jurisdiction.**

NetGuard enforces one guardrail for you, but you stay responsible for everything
else:

- The backend **refuses to start** until you list the subnet(s) you own in
  `backend/config.yaml` (`allowed_subnets`).
- The refused subnet is checked again **on every block action**, and blocking
  yourself or the gateway is not possible.
- Every action is written to a local timestamped log file.
- On shutdown / master-switch-off every ARP cache is automatically restored.

Use it only on networks you own or have written permission to test.

---

## Project layout

```
netguard/
├── run.bat                      # Windows launcher (self-elevates to Administrator)
├── run.sh                       # Linux/macOS launcher (re-launches with sudo)
├── backend/
│   ├── main.py                  # FastAPI app, REST + WebSocket, static serving, monitor
│   ├── usage.py                 # metered-usage store + quotas + CSV helpers
│   ├── qos.py                   # Windows QoS speed-cap helpers
│   ├── scanner.py               # ARP scan / liveness ping / hostname & vendor lookup / sniffing
│   ├── spoofer.py               # ARP spoofing engine (one thread per blocked device)
│   ├── models.py                # Pydantic API models
│   ├── config.yaml              # allow-listed subnets + tuning + log path
│   └── requirements.txt
└── frontend/
    ├── package.json             # Vite + React + Tailwind, pinned versions
    ├── vite.config.js           # dev proxy: /api → 127.0.0.1:8000 (REST + WS)
    └── src/                     # App.jsx, DeviceTable.jsx, useDevices.js, index.css …
```

---

## Setup

### Windows

1. **Install Npcap** → <https://npcap.com> (during install, tick *support raw
   802.11 traffic* only if you also want wireless monitoring; "WinPcap API
   compatible" default is fine).
2. Install **Python 3.11+** (python.org — tick *Add to PATH*) and **Node.js 18+**
   (nodejs.org).
3. Double-click **`run.bat`**. It self-elevates to Administrator, creates the
   venv, installs Python + npm dependencies, builds the frontend, starts the
   server and opens `http://127.0.0.1:8000` in your browser.
4. The first start **refuses to run on purpose**: open
   `backend/config.yaml` and allow-list your subnet — see *Configuration* below —
   then start `run.bat` again.

### Linux

```bash
sudo apt install python3 python3-venv python3-pip nodejs npm   # Debian/Ubuntu
sudo ./run.sh
# On Debian/Ubuntu you may need: sudo apt install libpcap-dev
```

### macOS

```bash
brew install python node
sudo ./run.sh
# If ARP sends fail: brew install libpcap, or grant packet capture
# permission to the terminal in System Settings → Privacy & Security.
```

### Manual (any OS, without the launcher)

```bash
python -m venv backend/venv
backend/venv/bin/python -m pip install -r backend/requirements.txt   # Windows: backend\venv\Scripts\pip

cd frontend && npm install && npm run build && cd ..

sudo backend/venv/bin/python backend/main.py    # Windows: run terminal as Administrator
# → http://127.0.0.1:8000
```

For UI development with hot reload: keep the backend running and run
`npm run dev` inside `frontend/` — Vite proxies `/api` (REST + WebSocket) to
port 8000.

---

## Configuration — `backend/config.yaml`

```yaml
allowed_subnets:          # ← NetGuard REFUSES to start while this is empty!
  - "192.168.1.0/24"      # your own subnet (Windows: `ipconfig`, Linux: `ip -4 r`)
scan_interval: 12         # seconds between live status pings
arp_scan_timeout: 2       # ARP reply wait (seconds)
spoof_interval: 2         # seconds between poison bursts per device
log_file: logs/netguard.log
server_port: 8000
```

If your subnet mask is not a standard /24 (NetGuard defaults to /24 when the OS
does not expose the mask), just set it here, e.g. `192.168.0.0/23`.

Optional: full vendor names for every NIC — uncomment `manuf` in
`backend/requirements.txt` and reinstall.

---

## Using the app

1. **Consent modal** — confirm you own the network (saved, shown once per browser).
2. **Scan network** — ARP sweep of the allow-listed subnet; results stream in as
   the WebSocket pushes snapshots (also between scans, passive sniffing keeps
   status fresh).
3. **Master switch** (`Protection active`) — enables/disables all spoofing at
   once. Every row toggle is disabled while protection is idle.
4. **Row toggle** — arms a per-device spoof thread (target and gateway are
   poisoned every 2 s). The device's status pill turns red *Blocked*.
5. Unblock or disabling the master switch — and closing the app — immediately
   sends corrective ARP packets so both ARP caches recover.
6. **Action log** — peek at `backend/logs/netguard.log` from the footer.

---
## Building a standalone installer

NetGuard ships as source. To produce a one-click Windows installer:

```bash
packaging\build.bat          # builds frontend + PyInstaller bundle -> dist\NetGuard\
```

Then open `packaging\installer.iss` in Inno Setup 6 and compile. The result
is `dist\NetGuard-Setup.exe`.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| "NetGuard is NOT running with elevated privileges" | Windows: start `run.bat` as Administrator. Linux/macOS: `sudo ./run.sh`. |
| Scan finds nothing / scapy errors | Windows: is **Npcap** installed? Linux: `sudo apt install libpcap-dev`. |
| Blocked devices come back online after ~30 s | Some router/APs detect ARP anomalies; NetGuard re-poisons every 2 s, which normally overrules this. |
| `pip` refuses the pinned scapy version on your Python | `pip install --upgrade scapy` inside the venv — any 2.5+ works. |
| Browser can't connect | Backend runs on `127.0.0.1:8000`; check the console window `run.bat` opened. |

**Note for wireless Linux setups:** some managed-mode Wi-Fi drivers filter
foreign ARP frames. NetGuard works best where raw ARP injection is allowed —
wired NICs or Wi-Fi adapters with Npcap/home-lab-friendly drivers. All home-lab
traffic goes to *your own* switch/AP only, so nothing you do here can leave your
subnet — another reason the allow-list exists.
