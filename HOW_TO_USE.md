# How to use NetGuard

The short version: **install three things, then double-click `run.bat`.**

## 1. Install (one time)

1. **Npcap** — https://npcap.com
   During install, keep the defaults ("WinPcap API compatible"). Tick
   *support raw 802.11 traffic* only if you want wireless monitoring.
2. **Python 3.11+** — https://python.org (tick **Add to PATH**).
3. **Node.js 18+** — https://nodejs.org (only needed the very first run,
   to build the web page).

## 2. First run

1. Double-click **`run.bat`**.
2. The first time, a console window appears and installs everything
   (Python packages + web page). This takes a minute or two. Wait for it.
3. The app refuses to start on purpose: it opens `backend/config.yaml`.
   Add your own Wi-Fi subnet, for example:
   ```yaml
   allowed_subnets:
     - "192.168.1.0/24"
   ```
   (Windows: `ipconfig` to find your subnet; Linux/macOS: `ip -4 r`.)
4. Double-click **`run.bat`** again. A small splash appears, then your
   browser opens on `http://127.0.0.1:8000`.

## 3. Everyday use

- Click the **NetGuard** icon on your desktop — no console window opens,
  the page appears directly.
- Click the **same icon again** to stop NetGuard (everything restores
  automatically).
- **Consent screen** (once): confirm it's your network.
- **Protection switch** (top right): turns all blocking on/off.
- **Row toggle** on a device: cuts that device off the internet.
- **Gauge icon** on a watched device: set speed limits (KB/s) and a daily
  data budget (MB).
- **Gear icon (Options)**: phone access passcode, start-with-Windows,
  alerts, and "Save a report" (CSV of usage).
- **Sun/Moon icon**: switch between dark and light look.

Everything restores itself automatically when you stop the app or turn
protection off.

## 4. Stop

Click the **NetGuard** desktop icon again — it stops the app and restores
everything automatically.

(Advanced: `stop.bat` is still available if you ever need it.)

## 5. Troubleshooting

| Problem | Fix |
|---|---|
| "not running with elevated privileges" | Right-click `run.bat` → Run as administrator. |
| Scan finds nothing | Is Npcap installed? |
| Browser can't connect | Backend runs on `127.0.0.1:8000`; check the console. |
| A device comes back online after ~30 s | NetGuard re-poisons every 2 s; usually resolves. |

## More

Full documentation: `README.md`. Source code and issues:
https://github.com/tebourbimalek/NetGuard
