"""
NShield - FastAPI backend + static frontend server.

Runs as a single local process:
  * REST API under /api/*
  * live device status over WebSocket /api/ws
  * serves frontend/dist as static files, so one URL = whole app

Start with:  python backend/main.py        (root / Administrator required)
The config allow-list in backend/config.yaml is checked BEFORE anything
starts; if the local IP is not inside an allowed subnet the process refuses
to run.
"""
from __future__ import annotations

import asyncio
import atexit
import http.client
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml
import uvicorn
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))     # allow `python backend/main.py` from repo root

import models   # noqa: E402
import scanner  # noqa: E402
import spoofer  # noqa: E402
import identify # noqa: E402
import usage    # noqa: E402
import qos      # noqa: E402
from usage import *  # noqa: E402,F403  (USAGE, usage_add, usage_totals, ...)
from qos import *    # noqa: E402,F403  (QOS_MIN_KBPS, qos_set_cap, qos_clear_cap)

VERSION = "1.0.0"

logger = logging.getLogger("nshield")

DEFAULT_CONFIG: Dict[str, object] = {
    "allowed_subnets": [],
    "scan_interval": 12,
    "arp_scan_timeout": 2,
    "spoof_interval": 2,
    "log_file": "logs/nshield.log",
    "server_port": 8000,
}


# --------------------------------------------------------------------------- #
# Known-device store (friendly names, icons, join alerts, phone access)
# Auto-managed in backend/data/known.json - config.yaml stays untouched.
# --------------------------------------------------------------------------- #

DATA_DIR = BASE_DIR / "data"
KNOWN_PATH = DATA_DIR / "known.json"
_known_lock = threading.RLock()

KNOWN: dict = {
    "names": {},       # mac -> {"name": str, "icon": str}
    "ack_macs": {},    # mac -> ISO timestamp of the last "new device" alert
    "settings": {"phone": False, "passcode": None, "alerts": True},
    "quotas": {},      # mac -> daily data budget in MB
}

ALLOWED_ICONS = [
    "phone", "tablet", "laptop", "desktop", "tv", "gamepad", "headphones",
    "printer", "router", "watch", "speaker", "unknown",
]

ALERT_REPEAT_HOURS = 24.0
_alert_warmup_until = 0.0     # set in main(): silent first scan after app start


# Automatic identification results, by MAC (identify.py). A device hints at
# its own kind (AirPlay/"Living Room", Chromecast, printer chatter...) and
# this feeds the automatic icon/name shown once nobody renamed it by hand.
IDENT_INFO: Dict[str, dict] = {}


def known_load() -> None:
    with _known_lock:
        try:
            with open(KNOWN_PATH, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict):
                for key in ("names", "ack_macs", "settings", "quotas"):
                    if isinstance(raw.get(key), dict):
                        KNOWN[key].update(raw[key])
            KNOWN["settings"]["phone"] = bool(KNOWN["settings"].get("phone"))
            KNOWN["settings"]["alerts"] = bool(KNOWN["settings"].get("alerts", True))
        except FileNotFoundError:
            pass
        except Exception as exc:
            logger.warning("known.json unreadable (%s) - starting fresh", exc)


def known_save() -> None:
    with _known_lock:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            tmp = KNOWN_PATH.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(KNOWN, fh, indent=2)
            os.replace(tmp, KNOWN_PATH)
        except Exception as exc:
            logger.warning("known.json could not be saved: %s", exc)


def passcode_value() -> str:
    """The phone-access passcode; a random 4-digit one is minted on first use."""
    with _known_lock:
        code = KNOWN["settings"].get("passcode")
        if not code:
            code = f"{secrets.randbelow(10000):04d}"
            KNOWN["settings"]["passcode"] = code
            known_save()
        return str(code)


def apply_known_names(rec: dict) -> None:
    """Stamp a device record with its saved friendly name / icon (by MAC)."""
    with _known_lock:
        meta = KNOWN["names"].get((rec.get("mac") or "").lower())
    if meta:
        rec["custom_name"] = meta.get("name") or None
        rec["icon"] = meta.get("icon") or None


def quota_of(mac_l: str) -> Optional[int]:
    """Daily data budget for a MAC in MB, or None."""
    with _known_lock:
        return KNOWN["quotas"].get(mac_l)


def windows_notify(title: str, text: str) -> None:
    """A small Windows toast (balloon) near the clock, best effort, hidden."""
    if sys.platform != "win32":
        return
    title = title.replace("'", " ").replace('"', " ")
    text = text.replace("'", " ").replace('"', " ")
    ps = (
        "Add-Type -AssemblyName System.Windows.Forms;"
        "Add-Type -AssemblyName System.Drawing;"
        "$n = New-Object System.Windows.Forms.NotifyIcon;"
        "$n.Icon = [System.Drawing.SystemIcons]::Information;"
        "$n.Visible = $true;"
        f"$n.ShowBalloonTip(6000, '{title}', '{text}', "
        "[System.Windows.Forms.ToolTipIcon]::Info);"
        "Start-Sleep -Seconds 7; $n.Dispose()"
    )
    try:
        subprocess.Popen(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        logger.warning("Windows notification failed: %s", exc)


def announce_new_device(state: "AppState", rec: dict) -> None:
    """
    Called (sniff thread / monitor thread) when a device joins that NShield
    has never alerted about before (re-alerts at most once per day). Pushes a
    live banner to the page and, if enabled, a Windows notification.
    """
    if not KNOWN["settings"].get("alerts", True):
        return
    now = time.time()
    if now < _alert_warmup_until:
        return                # the app's own first sweep - everything is "new"
    mac = (rec.get("mac") or "").lower()
    with _known_lock:
        last = KNOWN["ack_macs"].get(mac)
        if last:
            try:
                if (now - datetime.fromisoformat(last).timestamp()) < (
                    ALERT_REPEAT_HOURS * 3600
                ):
                    return
            except Exception:
                pass
        KNOWN["ack_macs"][mac] = datetime.fromtimestamp(
            now, tz=timezone.utc).isoformat(timespec="seconds")
        # keep the ack list bounded
        if len(KNOWN["ack_macs"]) > 500:
            KNOWN["ack_macs"] = dict(list(KNOWN["ack_macs"].items())[-250:])
        known_save()
    label = rec.get("custom_name") or rec.get("auto_name") \
        or rec.get("hostname") or rec.get("vendor") \
        or f"unknown device {rec.get('ip')}"
    logger.info("JOIN ALERT: %s (%s)", label, rec.get("ip"))
    windows_notify("NShield", f"A new device just joined your Wi-Fi: {label}")
    state.push_event({
        "type": "new_device",
        "device": {
            "ip": rec.get("ip"), "mac": rec.get("mac"),
            "custom_name": rec.get("custom_name"),
            "auto_name": rec.get("auto_name"),
            "hostname": rec.get("hostname"), "vendor": rec.get("vendor"),
        },
    })


def refresh_auto_suggest(rec: dict) -> None:
    """Recompute a record's automatic name/icon from what the network knows.
    Never overwrites names the user set by hand - those always win."""
    mac_l = (rec.get("mac") or "").lower()
    hints = IDENT_INFO.get(mac_l) or {}
    name, icon = identify.suggest(
        vendor=rec.get("vendor") or "",
        hostname=rec.get("hostname") or "",
        hints=hints,
    )
    rec["auto_name"] = name or None
    rec["auto_icon"] = icon or None


def identify_callback(mac: str, ip: str, info: dict) -> None:
    """
    Called from the sniffing thread whenever a device advertises itself
    (mDNS / SSDP). Merges the hints per MAC, refreshes the automatic
    name/icon on any matching device record, and refreshes the page.
    """
    state = APP_STATE
    if state is None:
        return
    mac = (mac or "").lower()
    if not mac:
        return
    try:
        if mac == (state.net.get("mac") or "").lower():
            return                       # our own announcements
        if ip and not scanner.is_ip_in_subnets(ip, state.subnets):
            return
    except Exception:
        pass

    merged = dict(IDENT_INFO.get(mac) or {})
    merged["services"] = sorted(set(merged.get("services") or [])
                                 | set(info.get("services") or []))
    merged["instance"] = info.get("instance") or merged.get("instance") or ""
    merged["server"] = info.get("server") or merged.get("server") or ""
    changed = merged != IDENT_INFO.get(mac)
    if changed or merged.get("hostname"):
        IDENT_INFO[mac] = merged

    # a clean hostname from the broadcast (e.g. "Saras-iPhone.local")
    host_from_mdns = (info.get("hostname") or "").strip()
    touched = False
    with state.lock:
        for rec in state.devices.values():
            if (rec.get("mac") or "").lower() != mac:
                continue
            if host_from_mdns and not rec.get("hostname"):
                rec["hostname"] = host_from_mdns
                touched = True
            if merged not in ({}, None) and (changed or touched):
                refresh_auto_suggest(rec)
                touched = True
    if changed or touched or host_from_mdns:
        logger.info("IDENT %s: %s -> %r (%s)", mac[:8], merged.get("services"),
                    (merged.get("instance") or "")[:28], merged.get("source"))
        push_presence_soon()


# --------------------------------------------------------------------------- #
# Gentle identification sweep: politely ASK silent devices who they are.
# Replies flow straight into identify_callback through the always-on listener.
# --------------------------------------------------------------------------- #

_MDNS_QUERY_SERVICES = [
    "_airplay._tcp.local",        # Apple TV / smart TVs
    "_raop._tcp.local",           # AirPlay audio (speakers)
    "_googlecast._tcp.local",     # Chromecast / Android TV
    "_androidtvremote2._tcp.local",
    "_companion-link._tcp.local", # iPhones / Macs give their real names
    "_ipp._tcp.local",            # printers
    "_spotify-connect._tcp.local",
    "_homekit._tcp.local",
]

_SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n\r\n"
)

_NBNS_QNAME = b"CK" + b"A" * 30      # wildcard "*" in NetBIOS first-level encoding
SWEEP_COOLDOWN = 10 * 60             # do not ask the same address twice in a row
_SWEPT: Dict[str, float] = {}        # ip -> last sweep ts


def _nbns_name_from_reply(raw: bytes) -> str:
    """Decode a NetBIOS node-status reply (RFC 1002 4.2.13) -> computer name."""
    try:
        idx = raw.find(b"\x00\x21\x00\x01")   # record type NBSTAT + class IN
        if idx < 0:
            return ""
        p = idx + 4
        rdlen = int.from_bytes(raw[p + 4:p + 6], "big")
        rd = raw[p + 6:p + 6 + rdlen]
        if len(rd) < 18 or int.from_bytes(rd[0:2], "big") < 1:
            return ""
        name = rd[2:18].decode("cp1252", "replace").strip(" \x00")
        if name and len(name) <= 16:
            return name
        return ""
    except Exception:
        return ""


def _probe_nbns(ip: str, mac: str, iface=None):
    """Ask a machine for its Windows (NetBIOS) name; None on silence."""
    from scapy.all import Raw, sr1
    try:
        query = (
            b"\x14\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            + b"\x20" + _NBNS_QNAME
            + b"\x00\x00\x21\x00\x01"
        )
        resp = sr1(
            IP(dst=ip) / UDP(sport=137, dport=137) / Raw(query),
            timeout=2, verbose=0, iface=iface,
        )
        if resp is None or not resp.haslayer(UDP):
            return None
        name = _nbns_name_from_reply(bytes(resp[UDP].payload))
        if not name or not re.search(r"[a-z0-9]", name, re.I):
            return None
        return {"mac": mac, "ip": ip, "services": [], "instance": name[:28],
                "hostname": "", "source": "nbns"}
    except Exception:
        return None


def identify_send(pkt, iface=None) -> None:
    """L3 send for the sweeps; wrapped so tests can observe calls."""
    from scapy.all import send
    send(pkt, verbose=0)          # L3: os routing picks the right interface


def identify_sweep_once(state: "AppState") -> int:
    now = time.time()
    asked = 0
    self_ip = state.net.get("ip")
    gw_ip = state.net.get("gateway_ip")
    with state.lock:
        unknowns = [
            r for r in state.device_records()
            if r["ip"] not in (self_ip, gw_ip)
            and not r.get("custom_name")
            and not r.get("auto_name")
            and r.get("online")
            and now - _SWEPT.get(r["ip"], 0) > SWEEP_COOLDOWN
        ]
    if not unknowns:
        return 0

    # 1. multicast name query burst (every device gets it, listeners answer)
    from scapy.all import DNS, DNSQR, IP, UDP
    send_step = max(0.05, 1.0 / max(1, len(_MDNS_QUERY_SERVICES)))
    try:
        for svc in _MDNS_QUERY_SERVICES:
            identify_send(
                IP(dst="224.0.0.251") / UDP(sport=5353, dport=5353) /
                DNS(rd=1, qd=DNSQR(qname=svc, qtype="PTR")),
            )
            time.sleep(send_step)
    except Exception as exc:
        logger.warning("IDENT sweep (name queries) failed: %s", exc)

    # 2. per device: UPnP "who are you" + Windows name request
    from scapy.all import IP, UDP, Raw
    for rec in unknowns:
        ip = rec["ip"]
        _SWEPT[ip] = now
        try:
            identify_send(
                IP(dst=ip) / UDP(sport=1900, dport=1900) / Raw(_SSDP_MSEARCH),
            )
        except Exception:
            pass
        info = _probe_nbns(ip, rec["mac"], state.iface_obj)
        if info is None:
            info = identify.web_probe(ip, rec["mac"])
        if info is not None:
            identify_callback(info["mac"], info["ip"], info)
        asked += 1
        time.sleep(0.15)
    if asked:
        logger.info("IDENT sweep: asked %d device(s) politely", asked)
    return asked


def identify_sweep_loop(state: "AppState") -> None:
    while not state.stop_evt.is_set():
        try:
            self_ip = state.net.get("ip")
            gw_ip = state.net.get("gateway_ip")
            need = any(
                r["ip"] not in (self_ip, gw_ip)
                and not r.get("custom_name")
                and not r.get("auto_name")
                and r.get("online")
                for r in state.device_records()
            )
            if need:
                identify_sweep_once(state)
        except Exception as exc:
            logger.warning("IDENT sweep loop error: %s", exc)
        state.stop_evt.wait(6.0)


# --------------------------------------------------------------------------- #
# Phone access (LAN reachability + passcode) and Windows auto-start
# --------------------------------------------------------------------------- #

AUTOSTART_TASK = "NShield"
PASS_HEADER = "x-nshield-pass"
OPEN_API_PATHS = {"/api/gate"}


def _ps_silent(args: List[str], timeout: int = 25) -> "subprocess.CompletedProcess":
    """Run a system command fully hidden; stdout/err captured for logging."""
    return subprocess.run(
        args, capture_output=True, timeout=timeout, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def autostart_status() -> bool:
    """True when the Windows scheduled task for auto-start exists and runs."""
    if sys.platform != "win32":
        return False
    try:
        result = _ps_silent(["schtasks", "/Query", "/TN", AUTOSTART_TASK])
        return result.returncode == 0
    except Exception:
        return False


def autostart_set(enable: bool) -> Tuple[bool, str]:
    """
    Start-with-Windows: a highest-privilege scheduled task at logon that
    launches the (windowless) starter, so the app comes up hidden and stays
    out of the way. Creating it needs elevation (the app already runs as
    Administrator), and no UAC prompt appears at each boot afterwards.
    """
    if sys.platform != "win32":
        return False, "Not supported on this system."
    if enable:
        vbs = (BASE_DIR / "elevated_run.vbs").resolve()
        result = _ps_silent([
            "schtasks", "/Create", "/TN", AUTOSTART_TASK,
            "/TR", f'wscript.exe "{vbs}"',
            "/SC", "ONLOGON", "/RL", "HIGHEST", "/F",
        ])
        ok = result.returncode == 0
        if ok:
            logger.info("AUTO-START enabled (Windows task '%s')", AUTOSTART_TASK)
            return True, "The app now starts by itself when Windows starts."
        detail = (result.stdout + result.stderr).decode(errors="replace")[:160]
        logger.warning("AUTO-START enable failed: %s", detail)
        return False, "Windows refused the automatic start - try again."
    result = _ps_silent(["schtasks", "/Delete", "/TN", AUTOSTART_TASK, "/F"])
    ok = result.returncode == 0
    logger.info("AUTO-START disabled (rc=%s)", result.returncode)
    return True, "The app no longer starts by itself."     # absent = already off


def firewall_rule_set(port: int, enable: bool) -> bool:
    """Open/close the Windows Firewall for the page port, so phones can reach it."""
    if sys.platform != "win32":
        return False
    rule = "NShield page"
    if enable:
        args = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule}", "dir=in", "action=allow", "protocol=TCP",
            f"localport={port}",
        ]
    else:
        args = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule}", "protocol=TCP", f"localport={port}",
        ]
    try:
        result = _ps_silent(args)
        ok = result.returncode == 0
        if ok:
            logger.info("FIREWALL %s port %d - %s",
                        "opened" if enable else "closed", port, rule)
        else:
            logger.warning(
                "FIREWALL change failed (port %d, enable=%s): %s", port, enable,
                (result.stdout + result.stderr).decode(errors="replace").strip()[:160]
            )
        return ok
    except Exception as exc:
        logger.warning("FIREWALL change errored: %s", exc)
        return False


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

def setup_logging(cfg: dict) -> Path:
    # Windows consoles are cp1252 by default; force UTF-8 with replacement so
    # logs never crash the process on weird characters.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    log_path = Path(cfg["log_file"])
    if not log_path.is_absolute():
        log_path = BASE_DIR / log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)

    handler = RotatingFileHandler(
        log_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s  %(levelname)-7s  %(name)s: %(message)s")
    )

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    # Windowless launch (pythonw.exe): there is no console to write to, so the
    # console log is skipped entirely instead of raising on every line.
    if sys.stdout is not None:
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(
            logging.Formatter("%(asctime)s  %(levelname)-7s  %(name)s: %(message)s")
        )
        root.addHandler(console)
    return log_path


def load_config() -> dict:
    cfg_path = BASE_DIR / "config.yaml"
    if not cfg_path.exists():
        sys.stderr.write(
            f"[{cfg_path}] not found.\n"
            "Create it from the shipped template (see README) before starting NShield.\n"
        )
        sys.exit(1)
    with open(cfg_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    if not isinstance(raw, dict):
        sys.stderr.write(f"[{cfg_path}] is not a valid YAML mapping.\n")
        sys.exit(1)
    cfg = {**DEFAULT_CONFIG, **raw}
    return cfg


def is_privileged() -> bool:
    """True when running as Administrator (Windows) or root (POSIX)."""
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def install_static_gateway_arp(net: dict, iface=None) -> bool:
    """
    Immunity for THIS machine against its own poison frames.

    Depending on the NIC/driver (Intel AX211 Wi-Fi observed), the frames we
    send via raw sockets can be looped back into the local TCP/IP stack and
    then Windows' own ARP table caches our poison ("gateway is-at our MAC"),
    which kills this host's connectivity from within. The classic defense is
    a permanent (static) neighbor-cache entry for the gateway: the kernel
    keeps it and does not overwrite it with dynamic ARP replies.

    Static entries enable requires admin (arp -s). Returns True on success.
    """
    if sys.platform != "win32":
        return False
    gw_ip = net.get("gateway_ip")
    our_ip = net["ip"]
    gw_mac = net.get("gateway_mac")
    if not gw_ip:
        logger.warning("Static gateway ARP skipped: no gateway IP known")
        return False
    if not gw_mac and iface is not None:
        try:
            gw_mac = scanner.arp_query_single(gw_ip, iface, timeout=2.0)
            if gw_mac:
                net["gateway_mac"] = gw_mac
        except Exception as exc:
            logger.warning("Gateway MAC probe for static ARP failed: %s", exc)
    if not gw_mac:
        logger.warning(
            "Static gateway ARP skipped: gateway MAC unknown (needs one "
            "successful ARP reply to install)"
        )
        return False
    try:
        subprocess.run(
            ["arp", "-d", gw_ip, our_ip],
            capture_output=True, timeout=5, check=False,
        )
        result = subprocess.run(
            ["arp", "-s", gw_ip, gw_mac.replace(":", "-"), our_ip],
            capture_output=True, timeout=5, check=False,
        )
        ok = result.returncode == 0
        if ok:
            logger.info("Static gateway ARP installed: %s is-at %s (self-poison immunity)",
                        gw_ip, gw_mac)
        else:
            logger.warning("Static gateway ARP failed: %s",
                           (result.stdout + result.stderr).decode(errors="replace").strip())
        return ok
    except Exception as exc:
        logger.warning("Static gateway ARP failed: %s", exc)
        return False


def neighbor_guard_loop(state: AppState) -> None:
    """
    Belt-and-braces healing: a one-packet OS ping to the gateway every few
    seconds forces the kernel to (re)resolve the gateway on its own whenever
    the static entry does not take, so our own stack can never stay in a
    self-poisoned state for long. Cheap, unprivileged, silent.
    """
    gw_ip = state.net["gateway_ip"]
    while not state.stop_evt.wait(3.0):
        try:
            subprocess.run(
                ["ping", "-n", "1", "-w", "400", gw_ip],
                capture_output=True, timeout=3,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                check=False,
            )
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Application state
# --------------------------------------------------------------------------- #

class AppState:
    """Process-wide state object shared by routes, monitor thread and sniffer."""

    def __init__(self, cfg: dict, net: dict, subnets: List["ipaddress.IPv4Network"],
                 log_path: Path, privileged: bool) -> None:
        self.cfg = cfg
        self.net = net
        self.subnets = subnets
        self.log_path = log_path
        self.privileged = privileged
        self.master = False
        self.compliant = True   # runtime mirror of the startup allow-list check
        self.router_ll: Optional[str] = None   # router IPv6 link-local (NDP)
        self._ll_fail_ts = 0.0                 # last failed NDP discovery moment
        self.stop_evt = threading.Event()
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.lock = threading.RLock()
        # The raw scapy interface object used for ALL packet I/O (the "iface"
        # string in net{} is only for display).
        self.iface_obj = net.pop("iface_obj", None) or net.get("iface")
        # The scanner placeholder is always False; stamp the real privilege
        # state so every WS snapshot (which serializes self.net verbatim)
        # matches what /api/self reports.
        net["privileged"] = privileged
        self.devices: "OrderedDict[str, dict]" = (
            OrderedDict()
        )  # ip -> {ip, mac, hostname, vendor, blocked, online, ts}
        # Checkpoint (usage metering) mode:
        self.watched: set = set()       # ips whose traffic flows through this PC
        self.traffic: Dict[str, dict] = {}  # ip -> {"down","up","down_rate","up_rate","since"}
        self.forwarding_on: bool = False    # Windows IP forwarding state we toggled
        self.engine = spoofer.SpoofEngine(
            iface=self.iface_obj,
            our_ip=net["ip"],
            our_mac=net["mac"],
            gateway_ip=net["gateway_ip"],
            spoof_interval=float(cfg["spoof_interval"]),
            resolve_gateway_mac=lambda ip: scanner.arp_query_single(
                ip, self.iface_obj, timeout=2.0
            ),
        )

    # -- registry helpers (all take self.lock) ------------------------------ #

    def upsert_device(self, ip: str, mac: str, hostname: str = "",
                      vendor: str = "", ts: Optional[float] = None) -> Optional[dict]:
        now = ts if ts is not None else time.time()
        mac_l = (mac or "").lower()
        # Never let another machine's record adopt OUR MAC. While a device is
        # blocked, a proxy-ARPing router can answer sweeps on its behalf with
        # the poisoned address (ours). Overwriting the real MAC would break
        # future blocks aimed at that device.
        if mac_l == self.net["mac"].lower() and ip != self.net["ip"]:
            with self.lock:
                rec = self.devices.get(ip)
                if rec is not None and rec["mac"].lower() != mac_l:
                    logger.warning(
                        "Ignored MAC update for %s: probe answered with our own "
                        "MAC (proxy-ARP while blocked) - keeping real MAC %s",
                        ip, rec["mac"],
                    )
            return None
        with self.lock:
            rec = self.devices.get(ip)
            if rec is None:
                rec = {
                    "ip": ip, "mac": mac, "hostname": hostname or "",
                    "vendor": vendor or "", "blocked": False,
                    "online": False, "ts": now,
                }
                apply_known_names(rec)
                refresh_auto_suggest(rec)
                self.devices[ip] = rec
                announce_new_device(self, rec)
            else:
                if hostname and not rec["hostname"]:
                    rec["hostname"] = hostname
                if vendor and not rec["vendor"]:
                    rec["vendor"] = vendor
                rec["mac"] = mac
                rec["ts"] = max(rec["ts"], now) if rec["ts"] else now
                refresh_auto_suggest(rec)
            return rec

    def device_records(self) -> List[dict]:
        with self.lock:
            return sorted(
                self.devices.values(),
                key=lambda r: _ip_key(r["ip"]),
            )

    def push_event(self, data: dict) -> None:
        """Thread-safe one-off WS push (join alerts etc.), no-op before open."""
        loop = self.loop
        if loop is not None and loop.is_running():
            asyncio.run_coroutine_threadsafe(manager.broadcast(data), loop)

    def ensure_router_ll(self) -> Optional[str]:
        """
        Discover the router's IPv6 link-local so the poison bursts can cover
        ICMPv6 NDP as well. Successful results are cached; failures are
        retried on later blocks (with a cooldown) so a first-second routing
        blip can never permanently disable IPv6 blocking. None => NDP half
        of the poisoning stays off (pure ARP/IPv4).
        """
        now = time.time()
        if self.router_ll:
            return self.router_ll
        if now - self._ll_fail_ts < 15.0:
            return None
        try:
            ll = scanner.router_link_local(
                self.iface_obj, self.net.get("gateway_mac") or "", timeout=6.0
            )
        except Exception as exc:
            logger.warning("IPv6 router discovery failed: %s", exc)
            ll = None
        if ll:
            self.router_ll = ll
            logger.info("IPv6 NDP support on: router link-local %s", ll)
            return ll
        self._ll_fail_ts = now
        logger.info(
            "IPv6 NDP support off for now: no router advertisement answered "
            "(will retry on the next block request)"
        )
        return None


def _ip_key(ip: str) -> Tuple[int, ...]:
    """Sort helper for dotted IPv4s."""
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999,)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().isoformat(timespec="seconds")


def device_model(rec: dict, traffic: Optional[Dict[str, dict]] = None) -> models.Device:
    flow = (traffic or {}).get(rec["ip"]) or {}
    mac_l = (rec.get("mac") or "").lower()
    with _known_lock:
        rec_quota = KNOWN["quotas"].get(mac_l)
    up_t, down_t = usage_totals(mac_l, day=_usage_day())
    up_m, down_m = usage_totals(mac_l, month_from=_month_start())
    return models.Device(
        ip=rec["ip"],
        mac=rec["mac"],
        hostname=rec.get("hostname") or "",
        vendor=rec.get("vendor") or "",
        online=rec.get("online", False),
        blocked=rec.get("blocked", False),
        watched=rec.get("watched", False),
        down_rate=float(flow.get("down_rate") or 0.0),
        up_rate=float(flow.get("up_rate") or 0.0),
        total_down=int(flow.get("down") or 0),
        total_up=int(flow.get("up") or 0),
        cap_down_kbps=flow.get("cap_down_kbps"),
        cap_up_kbps=flow.get("cap_up_kbps"),
        custom_name=rec.get("custom_name"),
        icon=rec.get("icon"),
        auto_name=rec.get("auto_name"),
        auto_icon=rec.get("auto_icon"),
        quota_mb=flow.get("quota_mb") if flow.get("quota_mb") is not None else rec_quota,
        used_today=float(flow.get("used_today") or (up_t + down_t)),
        used_month=float(flow.get("used_month") or (up_m + down_m)),
        watched_since=_iso(flow["since"]) if flow.get("since") else None,
        last_seen=_iso(rec["ts"]) if rec.get("ts") else None,
        last_poisoned=_iso(rec["poisoned_ts"]) if rec.get("poisoned_ts") else None,
    )


def snapshot(state: AppState) -> dict:
    records = state.device_records()
    return {
        "type": "snapshot",
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "master": state.master,
        "privileged": state.privileged,
        "compliant": state.compliant,
        "allowed_subnets": [str(s) for s in state.subnets],
        "net": state.net,
        "devices": [device_model(r, state.traffic).model_dump() for r in records],
    }


def broadcast_snapshot() -> None:
    """Thread-safe broadcast of a fresh snapshot (no-op outside the event loop)."""
    state = APP_STATE
    loop = state.loop
    if loop is not None and loop.is_running():
        asyncio.run_coroutine_threadsafe(
            manager.broadcast(snapshot(state)), loop
        )


# --------------------------------------------------------------------------- #
# WebSocket manager
# --------------------------------------------------------------------------- #

class ConnectionManager:
    def __init__(self) -> None:
        self._conns: List[WebSocket] = []
        self._lock = threading.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        with self._lock:
            self._conns.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        with self._lock:
            if ws in self._conns:
                self._conns.remove(ws)

    async def broadcast(self, data: dict) -> None:
        dead: List[WebSocket] = []
        text = json.dumps(data)
        with self._lock:
            conns = list(self._conns)
        for ws in conns:
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()
APP_STATE: Optional[AppState] = None


# --------------------------------------------------------------------------- #
# Background monitor + passive presence
# --------------------------------------------------------------------------- #

def refresh_network_state(state: AppState) -> None:
    """
    Runtime compliance watch, called once per monitor cycle with a cheap
    route-table lookup (no packets). If the default route moved to another
    interface, or the local IP left every allow-listed subnet, all spoofing
    is undone immediately, the master switch flips off, and every block
    request keeps refusing (HTTP 403) until the process restarts on a
    compliant network.
    """
    iface_name, out_ip, _gw_ip = scanner.quick_route()
    if not out_ip and not iface_name:
        return          # transient route-table blip; never flip on empty data

    inside = bool(out_ip) and scanner.is_ip_in_subnets(out_ip, state.subnets)
    iface_changed = bool(iface_name) and iface_name != state.net["iface"]
    if inside and not iface_changed:
        if not state.compliant:
            state.compliant = True
            logger.info(
                "Compliance regained - %s inside allowed subnets (%s)",
                out_ip, ", ".join(str(s) for s in state.subnets),
            )
        return

    was_armed = state.compliant or state.master or state.engine.count() > 0
    state.compliant = False
    if was_armed:
        logger.error(
            "COMPLIANCE LOST - detected %s on %s is not inside allowed_subnets "
            "(%s) - disarming everything",
            out_ip or "?", iface_name or "?",
            ", ".join(str(s) for s in state.subnets),
        )
        try:
            restored = state.engine.stop_all(restore=True)
        except Exception as exc:
            restored = 0
            logger.error("Emergency restore after compliance loss failed: %s", exc)
        try:
            release_all_watch(state)
        except Exception as exc:
            logger.error("Watch release after compliance loss failed: %s", exc)
        with state.lock:
            for rec in state.devices.values():
                rec["blocked"] = False
        state.master = False
        state.router_ll = None     # stale for the new network; rediscover lazily
        if restored:
            logger.error("Compliance guard: master OFF, %d device(s) restored", restored)
        if state.privileged:
            try:
                gw_mac = scanner.arp_query_single(
                    state.net["gateway_ip"], state.iface_obj, timeout=2.0
                )
                if gw_mac:
                    state.net["gateway_mac"] = gw_mac
                    install_static_gateway_arp(state.net, state.iface_obj)
                    state.router_ll = None     # refill for the new network lazily
            except Exception as exc:
                logger.warning("Static gateway ARP re-install failed: %s", exc)


def monitor_loop(state: AppState) -> None:
    """Periodic broadcast ARP ping -> online/offline statuses -> WS snapshot."""
    interval = max(3.0, float(state.cfg["scan_interval"]))
    ping_timeout = max(0.3, float(state.cfg["arp_scan_timeout"]))
    freshness = interval * 2.5        # passive-seen data stays valid this long

    while not state.stop_evt.wait(interval):
        try:
            now = time.time()
            pinged: Dict[str, str] = {}
            try:
                pinged = scanner.arp_ping_subnet(
                    state.net["cidr"], state.iface_obj, timeout=ping_timeout
                )
            except Exception as exc:
                logger.warning("Status ping failed: %s", exc)

            for ip, mac in pinged.items():
                state.upsert_device(ip, mac, ts=now)

            # this machine never answers its own ARP ping - keep it in the
            # list itself, permanently online
            state.upsert_device(
                state.net["ip"], state.net["mac"], hostname="Your PC", ts=now
            )

            with state.lock:
                for rec in state.devices.values():
                    if rec["ip"] == state.net["ip"]:
                        rec["online"] = True
                        rec["ts"] = now
                        continue
                    if rec["ip"] in pinged:
                        rec["online"] = True
                        rec["ts"] = now
                    else:
                        # offline unless the passive sniffer saw it recently
                        rec["online"] = bool(
                            rec["ts"] and (now - rec["ts"]) <= freshness
                        )

            # surface per-device "last poisoned" from the spoof engine
            poisoned = state.engine.last_poisoned()
            with state.lock:
                for ip, ts in poisoned.items():
                    rec = state.devices.get(ip)
                    if rec is not None:
                        rec["poisoned_ts"] = ts

            refresh_network_state(state)
            broadcast_snapshot()
        except Exception as exc:
            logger.error("Monitor cycle crashed: %s", exc)


_last_presence_push = 0.0
_presence_push_lock = threading.Lock()


def push_presence_soon() -> None:
    """
    Push a WS snapshot right after a join-style event, throttled to at most
    one push per second so join bursts never flood the browsers.
    """
    global _last_presence_push
    now = time.time()
    with _presence_push_lock:
        if now - _last_presence_push < 1.0:
            return
        _last_presence_push = now
    broadcast_snapshot()


def sniffer_callback(mac: str, ip: str) -> None:
    """Called from the sniff thread whenever a foreign host is seen."""
    state = APP_STATE
    if state is None:
        return
    try:
        is_new = state.devices.get(ip) is None
        state.upsert_device(ip, mac)
        if is_new:
            logger.info("Presence: %s (%s) appeared on the link", ip, mac)
            push_presence_soon()
    except Exception:
        pass


def dhcp_callback(mac: str, ip: str, hostname: str) -> None:
    """
    Called from the sniff thread when a device announces itself via DHCP
    (DISCOVER/REQUEST) - the join flow, so a just-connected phone shows up
    in the UI within a second.
    """
    state = APP_STATE
    if state is None:
        return
    try:
        if not ip:
            return                    # fresh DISCOVER without a usable address yet
        is_new = state.devices.get(ip) is None
        state.upsert_device(ip, mac, hostname=hostname)
        with state.lock:
            rec = state.devices.get(ip)
            if rec is not None:
                rec["online"] = True
                rec["ts"] = time.time()
        if is_new:
            logger.info("JOIN via DHCP: %s (%s%s)", ip, mac,
                        f", hostname {hostname}" if hostname else "")
            push_presence_soon()
    except Exception:
        pass


_shutdown_lock = threading.Lock()
_shutdown_done = False


# --------------------------------------------------------------------------- #
# Checkpoint mode: per-device data-usage metering
# --------------------------------------------------------------------------- #

def _is_local_ip(state: AppState, ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in state.subnets)


def _non_routable_ip(ip: str) -> bool:
    """Broadcast/multicast/link-local/reserved chatter is never 'internet'."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_multicast
        or int(addr) == 0xFFFFFFFF      # 255.255.255.255 flood
        or addr.is_link_local           # 169.254.*, fe80::
        or addr.is_loopback
        or addr.is_reserved
        or addr.is_unspecified
    )


def flow_callback(src_ip: str, dst_ip: str, nbytes: int) -> None:
    """
    Sniffer thread hook (checkpoint mode): attribute one routed packet to a
    watched device. Upload = device's IP is the source, download = device's
    IP is the destination. Packets that stay inside the local network, and
    our own machine's traffic, are not 'internet usage' and are skipped.
    """
    state = APP_STATE
    if state is None:
        return
    watched = state.watched
    if not watched:
        return
    src_l, dst_l = src_ip, dst_ip
    try:
        if src_l in watched:
            if not (_non_routable_ip(dst_ip) or _is_local_ip(state, dst_ip)):
                with state.lock:
                    flow = state.traffic.get(src_l)
                    if flow is not None:
                        flow["up"] += nbytes
        if dst_l in watched:
            if not (_non_routable_ip(src_ip) or _is_local_ip(state, src_ip)):
                with state.lock:
                    flow = state.traffic.get(dst_l)
                    if flow is not None:
                        flow["down"] += nbytes
    except Exception:
        pass                        # metering must never kill the sniffer


def set_forwarding(state: AppState, enable: bool, force: bool = False) -> bool:
    """
    Windows IP forwarding on the local interface - the checkpoint gate. When
    enabled, a watched device's packets are routed through this PC (both
    sides already believe the PC is the other endpoint) and become visible
    to the sniffer's counters. Persisted by Windows across app runs, so it
    is ALWAYS flipped back off when the last watched device is released,
    and force-reset at startup in case a previous run died mid-watch.
    """
    if not force and state.forwarding_on == enable:
        return True
    alias = state.net.get("iface_friendly") or ""
    word = "enabled" if enable else "disabled"
    ok = True
    for family in ("ipv4", "ipv6"):
        try:
            result = subprocess.run(
                ["netsh", "interface", family, "set", "interface", alias,
                 f"forwarding={word}"],
                capture_output=True, timeout=15, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode != 0:
                ok = False
                logger.warning(
                    "IP forwarding %s (%s) failed: %s", word, family,
                    result.stdout.decode(errors="replace").strip()
                    or result.stderr.decode(errors="replace").strip(),
                )
        except Exception as exc:
            ok = False
            logger.warning("IP forwarding %s (%s) failed: %s", word, family, exc)
    if ok:
        state.forwarding_on = enable
        logger.info("FORWARDING %s on %s", word.upper(), alias)
    return ok


def block_device_now(state: "AppState", rec: dict) -> Tuple[bool, str]:
    """Arm one device's block outside HTTP (quota engine + friends)."""
    if rec["ip"] in (state.net.get("ip"), state.net.get("gateway_ip")):
        return False, "refused"
    try:
        state.engine.block(
            rec["ip"],
            rec["mac"],
            router_ll=state.ensure_router_ll(),
            v6_addr_fn=lambda hwm=rec["mac"]: scanner.ipv6_profile(hwm),
        )
    except ValueError as exc:
        logger.warning("BLOCK-NOW %s refused: %s", rec["ip"], exc)
        return False, str(exc)
    except Exception as exc:
        logger.error("BLOCK-NOW %s failed: %s", rec["ip"], exc)
        return False, str(exc)
    with state.lock:
        rec["blocked"] = True
        rec["poisoned_ts"] = time.time()
    return True, ""


def _month_start() -> str:
    d = datetime.now().astimezone().date()
    return d.replace(day=1).isoformat()


def _device_label(rec: dict) -> str:
    return (rec.get("custom_name") or rec.get("auto_name")
            or rec.get("hostname") or rec.get("vendor") or rec.get("ip") or "?")


def quota_release_and_block(state: "AppState", ip: str) -> None:
    """Daily data budget reached while metering: release the watch, cut the
    device off, and tell the page + Windows."""
    rec = state.devices.get(ip)
    mac_l = (rec or {}).get("mac", "").lower()
    label = _device_label(rec) if rec else ip
    quota = KNOWN["quotas"].get(mac_l)
    released = release_watch(state, ip)
    ok = False
    if rec is not None:
        with state.lock:
            rec["watched"] = False
        ok, _ = block_device_now(state, rec)
    note = f"{label} reached today's data budget and is now offline."
    logger.info("QUOTA %s (%s) - released=%s, blocked=%s",
                label, ip, released, ok)
    windows_notify("NShield", note)
    state.push_event({
        "type": "notice",
        "text": f"{label} has used up today's data budget "
                f"({quota or 0} MB) - it is now offline.",
        "ip": ip,
    })
    broadcast_snapshot()


def flow_rate_loop(state: AppState) -> None:
    """
    One-second tick: turn raw byte counters into per-device down/up speeds
    (exponential moving average) and refresh the UI while anything is watched.
    """
    prev: Dict[str, Tuple[int, int]] = {}
    while not state.stop_evt.wait(1.0):
        try:
            with state.lock:
                watched = [ip for ip in state.watched if ip in state.traffic]
                counters = {
                    ip: (state.traffic[ip]["down"], state.traffic[ip]["up"])
                    for ip in watched
                }
                flows = {ip: state.traffic[ip] for ip in watched}
            now = time.time()
            changed = False
            quota_hits = []
            for ip in watched:
                d_now, u_now = counters.get(ip, (0, 0))
                d_prev, u_prev = prev.get(ip, (d_now, u_now))
                d_rate = max(0.0, d_now - d_prev)
                u_rate = max(0.0, u_now - u_prev)
                flow = flows.get(ip)
                if flow is not None:
                    dt = max(0.2, now - flow.get("rate_ts") or 1.0)
                    ema_down = 0.65 * flow["down_rate"] + 0.35 * (d_rate / dt)
                    ema_up = 0.65 * flow["up_rate"] + 0.35 * (u_rate / dt)
                    with state.lock:
                        flow["down_rate"] = ema_down
                        flow["up_rate"] = ema_up
                        flow["rate_ts"] = now
                    changed = True
                rec = state.devices.get(ip)
                if flow is not None and rec is not None:
                    mac_l = rec["mac"].lower()
                    quota = KNOWN["quotas"].get(mac_l)
                    usage_flush_flow(state, ip, flow)   # book session bytes
                    up_t, down_t = usage_totals(mac_l, day=_usage_day())
                    up_m, down_m = usage_totals(mac_l, month_from=_month_start())
                    with state.lock:
                        flow["quota_mb"] = quota
                        flow["used_today"] = up_t + down_t
                        flow["used_month"] = up_m + down_m
                    if quota and (up_t + down_t) >= quota * 1024 * 1024:
                        quota_hits.append(ip)
            prev = counters
            if changed:
                broadcast_snapshot()
            for ip in quota_hits:
                quota_release_and_block(state, ip)
        except Exception as exc:
            logger.warning("Usage rate tick failed: %s", exc)


def release_watch(state: AppState, ip: str, stop_forwarding: bool = True) -> bool:
    """
    Stop metering one device: restore its ARP/NDP truth, drop its counters,
    and (by default) switch forwarding back off when the last watch ends.
    """
    was_watched = ip in state.watched
    if was_watched:
        state.watched.discard(ip)
    restored = state.engine.unblock(ip) if was_watched else False
    # book the final session bytes into the history before dropping counters
    flow = state.traffic.get(ip)
    if flow is not None:
        usage_flush_flow(state, ip, flow)
    # speed caps die with the watch - never leave a QoS policy behind
    qos_clear_cap(state, ip, "down")
    qos_clear_cap(state, ip, "up")
    with state.lock:
        rec = state.devices.get(ip)
        if rec is not None:
            rec["watched"] = False
        state.traffic.pop(ip, None)
    if not state.watched and stop_forwarding and state.forwarding_on:
        set_forwarding(state, False)
    if was_watched:
        logger.info("WATCH %s - metering stopped", ip)
    return restored or was_watched


def release_all_watch(state: AppState) -> int:
    """Stop metering every watched device (master-off / restore / shutdown)."""
    n = len(state.watched)
    if not n:
        return 0
    with state.lock:                       # book every session's last bytes
        flows = dict(state.traffic)
    for ip, flow in flows.items():
        usage_flush_flow(state, ip, flow)
    usage_save()
    stopped = state.engine.stop_all(restore=True)
    for ip in list(state.watched):
        qos_clear_cap(state, ip, "down")
        qos_clear_cap(state, ip, "up")
    with state.lock:
        state.watched.clear()
        state.traffic.clear()
        for rec in state.devices.values():
            rec["watched"] = False
    if state.forwarding_on:
        set_forwarding(state, False)
    logger.info("WATCH-STOP - %d device(s) released from metering", n)
    return n + (stopped if stopped else 0)


def shutdown_restore() -> None:
    """
    Idempotent emergency restore - called from the FastAPI lifespan shutdown
    AND registered with atexit, so it runs at least once (and possibly twice.
    The second invocation is a logged no-op: the drain lock serializes
    concurrent calls and the flag short-circuits duplicates.
    """
    global _shutdown_done
    state = APP_STATE
    if state is None:
        return
    with _shutdown_lock:
        if _shutdown_done:
            logger.debug("SHUTDOWN restore already processed - skipping duplicate call")
            return
        _shutdown_done = True
    try:
        release_all_watch(state)               # metering off + forwarding off
        n = state.engine.stop_all(restore=True)
        if n:
            logger.info("SHUTDOWN - restored %d device(s)", n)
        else:
            logger.info("SHUTDOWN - nothing to restore, ARP tables already clean")
    except Exception as exc:
        logger.error("Shutdown restore failed: %s", exc)


# --------------------------------------------------------------------------- #
# FastAPI app
# --------------------------------------------------------------------------- #

@asynccontextmanager
async def lifespan(app: FastAPI):
    state = APP_STATE
    assert state is not None
    state.loop = asyncio.get_running_loop()

    logger.info("NShield backend v%s started - http://127.0.0.1:%s (privileged=%s)",
                VERSION, state.cfg["server_port"], state.privileged)
    if not state.privileged:
        explain_privileges("warning")

    scanner.start_passive_sniffer(
        state.iface_obj,
        state.stop_evt,
        sniffer_callback,
        our_mac=state.net["mac"],
        subnets=state.subnets,
        on_dhcp=dhcp_callback,
        on_flow=flow_callback,
        on_identify=identify_callback,
    )
    threading.Thread(
        target=identify_sweep_loop, args=(state,), name="nshield-ident", daemon=True
    ).start()
    threading.Thread(
        target=monitor_loop, args=(state,), name="nshield-monitor", daemon=True
    ).start()
    threading.Thread(
        target=flow_rate_loop, args=(state,), name="nshield-flow-rates", daemon=True
    ).start()
    threading.Thread(
        target=neighbor_guard_loop, args=(state,), name="nshield-neighbor-guard", daemon=True
    ).start()

    yield

    state.stop_evt.set()
    shutdown_restore()


def explain_privileges(level: str = "warning") -> None:
    if sys.platform == "win32":
        msg = (
            "NShield is NOT running as Administrator. ARP spoofing needs raw "
            "sockets: start run.bat as Administrator and make sure Npcap is "
            "installed (https://npcap.com)."
        )
    else:
        msg = (
            "NShield is NOT running as root. ARP spoofing needs raw sockets: "
            "run `sudo ./run.sh` (Linux/macOS)."
        )
    if level == "notice":
        logger.warning(msg)
    else:
        logger.error(msg)


app = FastAPI(title="NShield", version=VERSION, lifespan=lifespan)


# ------------------------------ REST routes ------------------------------ #

@app.get("/api/self")
def get_self():
    state = APP_STATE
    return {
        "version": VERSION,
        "net": models.NetworkInfo(**{**state.net, "privileged": state.privileged}).model_dump(),
        "master": state.master,
        "compliant": state.compliant,
        "allowed_subnets": [str(s) for s in state.subnets],
        "blocked_count": state.engine.count(),
    }


@app.get("/api/devices", response_model=models.DeviceListResponse)
def get_devices():
    state = APP_STATE
    return {
        "devices": [device_model(r, state.traffic) for r in state.device_records()],
        "master": state.master,
    }


@app.post("/api/scan", response_model=models.ScanResponse)
def scan():
    """Full ARP sweep of the configured subnet + hostname/vendor resolution."""
    state = APP_STATE
    require_privileged(state)
    cidr = state.net["cidr"]
    logger.info("SCAN start %s on %s", cidr, state.net["iface_friendly"])

    hosts = scanner.arp_ping_subnet(
        cidr,
        state.iface_obj,
        timeout=max(0.5, float(state.cfg["arp_scan_timeout"])),
    )
    hostnames = scanner.resolve_hostnames(list(hosts.keys())) if hosts else {}
    for ip, mac in hosts.items():
        state.upsert_device(
            ip,
            mac,
            hostname=hostnames.get(ip, ""),
            vendor=scanner.vendor_lookup.lookup(mac),
        )
    broadcast_snapshot()
    logger.info("SCAN done: %d device(s) answered", len(hosts))
    return models.ScanResponse(
        devices=[device_model(r, state.traffic) for r in state.device_records()],
        scanned_cidr=cidr,
    )


def require_privileged(state: AppState) -> None:
    if not state.privileged:
        raise HTTPException(
            status_code=403,
            detail=(
                "NShield needs elevated privileges. "
                + ("run.bat as Administrator + Npcap (Windows)."
                   if sys.platform == "win32"
                   else "sudo ./run.sh (Linux/macOS).")
            ),
        )


def require_master_on(state: AppState) -> None:
    if not state.master:
        raise HTTPException(
            status_code=409,
            detail="Global protection is off - flip the master switch first.",
        )


def require_compliant(state: AppState) -> None:
    """Refuse offensive actions when the network no longer matches config.yaml."""
    if not state.compliant:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Network mismatch: detected {state.net['cidr']} is not inside "
                f"allowed_subnets ({', '.join(str(s) for s in state.subnets)}). "
                "Update backend/config.yaml and restart NShield."
            ),
        )


@app.post("/api/block", response_model=models.ActionResponse)
async def block_device(req: models.BlockRequest):
    state = APP_STATE
    require_privileged(state)
    require_master_on(state)
    require_compliant(state)

    ip = req.ip
    if ip == state.net["ip"]:
        raise HTTPException(400, "You cannot block this machine itself.")
    if ip == state.net["gateway_ip"]:
        raise HTTPException(400, "Refusing to block the gateway - that would cut off everyone.")

    rec = next((r for r in state.device_records() if r["ip"] == ip), None)
    if rec is None:
        raise HTTPException(404, "Unknown device - run a scan first.")
    if not scanner.is_ip_in_subnets(ip, state.subnets):
        raise HTTPException(
            403,
            f"{ip} is outside the subnets allow-listed in backend/config.yaml.",
        )
    if state.watched:
        raise HTTPException(
            409,
            "Usage watching is on for some device(s). Stop watching first "
            "(watching and cutting off cannot run at the same time).",
        )

    try:
        router_ll = state.ensure_router_ll()
        hwm = rec["mac"]
        state.engine.block(
            ip,
            hwm,
            router_ll=router_ll,
            v6_addr_fn=lambda hwm=hwm: scanner.ipv6_profile(hwm),
        )
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    except RuntimeError as exc:
        raise HTTPException(502, str(exc))

    with state.lock:
        rec["blocked"] = True
        rec["poisoned_ts"] = time.time()
    logger.info("BLOCK %s (%s) - spoof thread armed", ip, rec["mac"])
    await manager.broadcast(snapshot(state))
    return models.ActionResponse(ok=True, message=f"{ip} is now blocked.")


@app.post("/api/unblock", response_model=models.ActionResponse)
async def unblock_device(req: models.BlockRequest):
    state = APP_STATE
    require_privileged(state)

    ip = req.ip
    found = state.engine.unblock(ip)
    with state.lock:
        rec = state.devices.get(ip)
        if rec is not None:
            rec["blocked"] = False
    if found:
        logger.info("UNBLOCK %s - ARP restoration sent", ip)
    else:
        logger.info("UNBLOCK %s - was not blocked (no-op)", ip)
    await manager.broadcast(snapshot(state))
    return models.ActionResponse(ok=True, message=f"{ip} unblocked, caches restored.")


@app.post("/api/master", response_model=models.ActionResponse)
async def set_master(req: models.MasterRequest):
    state = APP_STATE
    if req.enabled:
        require_privileged(state)
        require_compliant(state)

    if req.enabled:
        state.master = True
        logger.info("MASTER SWITCH -> ON")
    else:
        state.master = False
        released = release_all_watch(state)
        restored = state.engine.stop_all(restore=True)
        with state.lock:
            for rec in state.devices.values():
                rec["blocked"] = False
        logger.info(
            "MASTER SWITCH -> OFF - %d device(s) restored, %d watch(s) released",
            restored, released,
        )

    await manager.broadcast(snapshot(state))
    return models.ActionResponse(
        ok=True, message=f"Protection {'active' if req.enabled else 'disabled'}."
    )


@app.post("/api/shutdown", response_model=models.ActionResponse)
async def api_shutdown():
    """Restore everything and exit - used by the desktop toggle."""
    state = APP_STATE
    if state is None:
        return models.ActionResponse(ok=True, message="Nothing to stop.")
    try:
        restored = state.engine.stop_all(restore=True)
    except Exception as exc:
        restored = 0
        logger.error("Shutdown restore failed: %s", exc)
    try:
        release_all_watch(state)
    except Exception as exc:
        logger.error("Shutdown watch release failed: %s", exc)
    with state.lock:
        for rec in state.devices.values():
            rec["blocked"] = False
        state.master = False
    logger.info("SHUTDOWN requested - %d device(s) restored", restored)

    def _exit_later():
        time.sleep(1.5)
        try:
            os._exit(0)
        except Exception:
            sys.exit(0)
    threading.Thread(target=_exit_later, daemon=True).start()
    return models.ActionResponse(ok=True, message="NShield is stopping. Everything is restored.")


@app.post("/api/restore-all", response_model=models.ActionResponse)
async def restore_all():
    """
    Send restoration ARP packets for every blocked device WITHOUT touching
    the master switch - the safety counterpart of "block all". Also stops
    any usage-metering watches (forwarding back off).
    """
    state = APP_STATE
    require_privileged(state)
    released = release_all_watch(state)
    restored = state.engine.stop_all(restore=True)
    with state.lock:
        for rec in state.devices.values():
            rec["blocked"] = False
    master_word = "ON" if state.master else "OFF"
    if restored or released:
        logger.info(
            "RESTORE-ALL - %d device(s) restored, %d watch(s) released, "
            "master stays %s", restored, released, master_word,
        )
    else:
        logger.info("RESTORE-ALL - nothing was blocked, master stays %s",
                    master_word)
    await manager.broadcast(snapshot(state))
    return models.ActionResponse(
        ok=True,
        message=f"All devices restored ({restored} active block(s) lifted, "
                f"{released} watch(es) released).",
    )


WATCH_CONFLICT = (
    "Stop watching usage first: watching and cutting off cannot run at the "
    "same time."
)


def _norm_cap_value(value: Optional[int]) -> Optional[int]:
    """Cap KB/s sanity: <=0/None -> None (no limit); floor at QOS_MIN_KBPS."""
    if value is None:
        return None
    if value <= 0:
        return None
    return max(int(value), QOS_MIN_KBPS)


@app.post("/api/cap", response_model=models.ActionResponse)
async def set_cap(req: models.CapRequest):
    """
    Speed caps for a WATCHED device, enforced by Windows QoS throttling on
    the packets this PC relays: down cap on dst=device traffic, up cap on
    src=device traffic. Works only while the device is being watched.
    kbps <= 0 / None = no limit.
    """
    state = APP_STATE
    require_privileged(state)
    ip = req.ip
    if ip not in state.watched:
        raise HTTPException(
            409, "Limits can only be set while the device is being watched."
        )
    with state.lock:
        flow = state.traffic.get(ip)
    if flow is None:
        raise HTTPException(409, "No live counters for this device - re-watch it first.")

    down_kbps = _norm_cap_value(req.down_kbps)
    up_kbps = _norm_cap_value(req.up_kbps)
    with state.lock:
        rec = state.devices.get(ip)
    quota_note = ""
    if req.quota_mb is not None:
        quota_mb = max(0, int(req.quota_mb))
        with state.lock:
            rec = state.devices.get(ip)
        mac_l = (rec["mac"] if rec else "").lower()
        if mac_l:
            with _known_lock:
                if quota_mb > 0:
                    KNOWN["quotas"][mac_l] = quota_mb
                    logger.info("QUOTA-SET %s daily budget %d MB", mac_l, quota_mb)
                else:
                    KNOWN["quotas"].pop(mac_l, None)
                    logger.info("QUOTA-CLR %s", mac_l)
                known_save()
            quota_note = (f", daily budget {quota_mb} MB"
                          if quota_mb > 0 else ", daily budget removed")
    try:
        # Policy store churn is cheap and idempotent; apply both sides fresh.
        qos_clear_cap(state, ip, "down")
        qos_clear_cap(state, ip, "up")
        if down_kbps is not None and not qos_set_cap(state, ip, "down", down_kbps):
            down_kbps = None
            logger.warning("CAP %s download limit could not be installed", ip)
        if up_kbps is not None and not qos_set_cap(state, ip, "up", up_kbps):
            up_kbps = None
            logger.warning("CAP %s upload limit could not be installed", ip)
    finally:
        with state.lock:
            flow["cap_down_kbps"] = down_kbps
            flow["cap_up_kbps"] = up_kbps
    down_word = f"{down_kbps} KB/s" if down_kbps else "no limit"
    up_word = f"{up_kbps} KB/s" if up_kbps else "no limit"
    logger.info("CAP-SET %s download %s, upload %s%s", ip, down_word, up_word, quota_note)
    await manager.broadcast(snapshot(state))
    return models.ActionResponse(
        ok=True,
        message=f"Download {down_word}, upload {up_word}{quota_note}.",
    )


@app.post("/api/watch", response_model=models.ActionResponse)
async def set_watch(req: models.WatchRequest):
    """
    Checkpoint mode per device: route its traffic through this PC so the
    sniffer can meter download/upload. Uses the same poison pair as blocking
    (ARP + NDP), but with Windows IP forwarding ON so packets are relayed
    and counted instead of dropped. Mutually exclusive with blocking.
    """
    state = APP_STATE
    require_privileged(state)
    ip = req.ip

    if req.enabled:
        require_master_on(state)
        require_compliant(state)
        blocked = [r["ip"] for r in state.device_records() if r["blocked"]]
        if blocked:
            raise HTTPException(409, WATCH_CONFLICT)
        if ip == state.net["ip"]:
            raise HTTPException(400, "You cannot watch your own computer.")
        if ip == state.net["gateway_ip"]:
            raise HTTPException(400, "The router's traffic cannot be metered by the app.")
        if ip in state.watched:
            return models.ActionResponse(ok=True, message=f"{ip} is already being watched.")
        rec = next((r for r in state.device_records() if r["ip"] == ip), None)
        if rec is None:
            raise HTTPException(404, "Unknown device - run a scan first.")
        if not scanner.is_ip_in_subnets(ip, state.subnets):
            raise HTTPException(
                403,
                f"{ip} is outside the subnets allow-listed in backend/config.yaml.",
            )
        mac_l = rec["mac"].lower()
        quota = KNOWN["quotas"].get(mac_l)
        if quota:
            up_t, down_t = usage_totals(mac_l, day=_usage_day())
            if (up_t + down_t) >= quota * 1024 * 1024:
                # already past today's budget: disconnect instead of Watching
                with state.lock:
                    rec["watched"] = True          # temporarily, for release below
                    state.traffic[ip] = {
                        "down": 0, "up": 0, "down_rate": 0.0, "up_rate": 0.0,
                        "up_c": 0, "down_c": 0,
                        "since": time.time(), "rate_ts": time.time(),
                    }
                    state.watched.add(ip)
                quota_release_and_block(state, ip)
                await manager.broadcast(snapshot(state))
                return models.ActionResponse(
                    ok=True,
                    message=f"{_device_label(rec)} already reached today's "
                            f"data budget ({quota} MB) - it stays offline "
                            "until tomorrow or until the budget is changed.",
                )

        try:
            router_ll = state.ensure_router_ll()
            hwm = rec["mac"]
            state.engine.block(
                ip,
                hwm,
                router_ll=router_ll,
                v6_addr_fn=lambda hwm=hwm: scanner.ipv6_profile(hwm),
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        except RuntimeError as exc:
            raise HTTPException(502, str(exc))

        # Forwarding must be live BEFORE the device starts sending through us.
        if not set_forwarding(state, True):
            state.engine.unblock(ip)
            raise HTTPException(
                502, "Detecting that traffic would pass through the app failed "
                "(forwarding could not be enabled)."
            )
        with state.lock:
            state.watched.add(ip)
            rec["watched"] = True
            rec["poisoned_ts"] = time.time()
            state.traffic[ip] = {
                "down": 0, "up": 0,
                "down_rate": 0.0, "up_rate": 0.0,
                "up_c": 0, "down_c": 0,
                "since": time.time(), "rate_ts": time.time(),
            }
        logger.info(
            "WATCH %s (%s) - metering on, traffic relayed through this "
            "machine to count it", ip, rec["mac"]
        )
        await manager.broadcast(snapshot(state))
        return models.ActionResponse(ok=True, message=f"Now watching {ip}.")

    # ---- disable ---------------------------------------------------------- #
    was = release_watch(state, ip)
    if not was:
        return models.ActionResponse(ok=True, message=f"{ip} was not watched.")
    await manager.broadcast(snapshot(state))
    return models.ActionResponse(ok=True, message=f"{ip} released, caches restored.")


# ------------------------- phone-access gate ----------------------------- #
# When phone access is on, every /api/* call that does not come from this
# computer must carry the passcode (header from the page, query param for
# the live status socket). The page HTML itself stays open, so phones can
# always load the "enter passcode" screen.

def _is_local(request: Request) -> bool:
    try:
        host = request.client.host if request.client else ""
        return ipaddress.ip_address(host).is_loopback
    except Exception:
        return False        # unknown origin -> treat as remote (stricter)


def _pass_ok(request: Request) -> bool:
    supplied = (
        request.headers.get(PASS_HEADER)
        or request.query_params.get("pass")
        or ""
    )
    try:
        return secrets.compare_digest(str(supplied), passcode_value())
    except Exception:
        return False


_PASS_FAILS: dict = {}          # client ip -> list of failure timestamps
_PASS_LOCK = threading.RLock()
_PASS_MAX_FAILS = 5
_PASS_WINDOW = 60               # seconds


def _record_pass_failure(ip: str) -> None:
    now = time.time()
    with _PASS_LOCK:
        lst = [t for t in _PASS_FAILS.get(ip, []) if now - t < _PASS_WINDOW]
        lst.append(now)
        _PASS_FAILS[ip] = lst


def _pass_rate_limited(ip: str) -> bool:
    now = time.time()
    with _PASS_LOCK:
        lst = [t for t in _PASS_FAILS.get(ip, []) if now - t < _PASS_WINDOW]
        _PASS_FAILS[ip] = lst
        return len(lst) >= _PASS_MAX_FAILS


def needs_pass(request: Request) -> bool:
    return (
        bool(KNOWN["settings"].get("phone"))
        and not _is_local(request)
        and not _pass_ok(request)
    )


@app.middleware("http")
async def phone_gate(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api") and path not in OPEN_API_PATHS:
        client_ip = request.client.host if request.client else ""
        if _pass_rate_limited(client_ip):
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many wrong passcode attempts. Try again in a minute."},
            )
        if needs_pass(request):
            # count only real attempts (a passcode was supplied but did not match)
            if request.headers.get("x-nshield-pass"):
                _record_pass_failure(client_ip)
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=401,
                content={"detail": "Please enter the NShield passcode."},
            )
    return await call_next(request)


@app.get("/api/gate", response_model=models.GateResponse)
def api_gate(request: Request):
    """The page asks this before showing the device list or a passcode box."""
    return models.GateResponse(needed=needs_pass(request))


@app.post("/api/rename", response_model=models.ActionResponse)
async def api_rename(req: models.RenameRequest):
    """Remember a friendly name (and icon) for a device, keyed by its MAC."""
    state = APP_STATE
    mac = req.mac.strip().lower()
    if not mac:
        raise HTTPException(400, "Missing the device to rename.")
    name = " ".join(req.name.split())[:28]
    icon = req.icon if req.icon in ALLOWED_ICONS else ""
    with _known_lock:
        if not name and not icon:
            KNOWN["names"].pop(mac, None)
        else:
            KNOWN["names"][mac] = {"name": name, "icon": icon}
            known_save()
    with state.lock:
        changed = 0
        for rec in state.devices.values():
            if (rec.get("mac") or "").lower() == mac:
                if name:
                    rec["custom_name"] = name
                    rec["icon"] = icon or rec.get("icon")
                elif icon:
                    rec["icon"] = icon
                    rec["custom_name"] = None
                else:
                    rec["custom_name"] = None
                    rec["icon"] = None
                changed += 1
    logger.info("RENAME %s -> name '%s', icon '%s'", mac, name or "(cleared)",
                icon or "-")
    await manager.broadcast(snapshot(state))
    return models.ActionResponse(
        ok=True,
        message=f"Renamed ({changed} device record(s) updated).",
    )


@app.get("/api/settings", response_model=models.SettingsResponse)
def api_settings(request: Request):
    state = APP_STATE
    port = int(state.cfg["server_port"])
    lan_url = f"http://{state.net['ip']}:{port}"
    with _known_lock:
        code = passcode_value()
        phone = bool(KNOWN["settings"].get("phone"))
        alerts = bool(KNOWN["settings"].get("alerts", True))
    return models.SettingsResponse(
        phone_access=phone,
        passcode=code,
        lan_url=lan_url,
        alerts_on=alerts,
        autostart=autostart_status(),
    )


@app.post("/api/settings", response_model=models.ActionResponse)
async def api_settings_update(update: models.SettingsUpdate):
    state = APP_STATE
    port = int(state.cfg["server_port"])
    notes: List[str] = []

    with _known_lock:
        settings = KNOWN["settings"]
        if update.passcode is not None:
            code = update.passcode.strip()
            if len(code) < 4 or len(code) > 12:
                raise HTTPException(400, "The passcode needs 4 to 12 characters.")
            settings["passcode"] = code
            logger.info("SETTINGS passcode changed (%d chars)", len(code))
        if update.alerts_on is not None:
            settings["alerts"] = bool(update.alerts_on)
            notes.append(f"join alerts {'on' if update.alerts_on else 'off'}")
        want_phone = update.phone_access if update.phone_access is not None else None
        want_start = update.autostart

        if want_phone is not None and want_phone != bool(settings.get("phone")):
            if want_phone:
                if firewall_rule_set(port, True):
                    settings["phone"] = True
                    notes.append("phone access enabled")
                else:
                    raise HTTPException(
                        502,
                        "Opening the connection for your phone failed "
                        "(needs the app running with admin permission).",
                    )
            else:
                firewall_rule_set(port, False)
                settings["phone"] = False
                notes.append("phone access disabled")
            known_save()

    if want_start is not None:
        ok, message = autostart_set(bool(want_start))
        if not ok:
            raise HTTPException(502, message)
        notes.append(f"start with Windows {'on' if want_start else 'off'}")

    known_save()
    logger.info("SETTINGS updated: %s", "; ".join(notes) or "(no change)")
    return models.ActionResponse(
        ok=True, message="; ".join(notes) or "Nothing changed."
    )


@app.get("/api/export")
def export_usage(days: int = 30):
    """
    One spreadsheet: every metered device-day on record (names, addresses,
    uploaded / downloaded). Phones need the passcode like every /api call.
    """
    days = max(1, min(int(days), 365))
    state = APP_STATE
    by_mac: Dict[str, dict] = {}          # mac -> {"name": ..., "ip": ...}
    with state.lock:
        for rec in state.device_records():
            mac_l = (rec.get("mac") or "").lower()
            if mac_l:
                by_mac[mac_l] = {"name": _device_label(rec), "ip": rec["ip"]}
    with _known_lock:
        for mac_l, meta in KNOWN["names"].items():
            slot = by_mac.setdefault(mac_l, {"name": "", "ip": ""})
            slot["name"] = slot["name"] or meta.get("name") or ""
    lines = [
        "date,name,ip,mac,uploaded_mb,downloaded_mb"
    ]
    cutoff = (datetime.now().astimezone().date() - timedelta(days=days - 1)).isoformat()
    with _usage_lock:
        for day in sorted(USAGE["days"]):
            if day < cutoff:
                continue
            for mac_l, totals in sorted(USAGE["days"][day].items()):
                slot = by_mac.get(mac_l, {})
                up_mb = int(totals.get("up", 0)) / (1024 * 1024)
                down_mb = int(totals.get("down", 0)) / (1024 * 1024)
                if up_mb < 0.01 and down_mb < 0.01:
                    continue
                lines.append(
                    f"{day},"
                    + (slot.get("name") or "Unknown").replace(",", " ")
                    + f",{slot.get('ip') or ''},{mac_l},"
                    f"{up_mb:.2f},{down_mb:.2f}"
                )
    body = "\n".join(lines) + "\n"
    logger.info("EXPORT csv - %s row(s), last %d day(s)", len(lines) - 1, days)
    from fastapi.responses import Response
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="nshield-usage.csv"'},
    )


@app.get("/api/logs", response_model=models.LogResponse)
def read_logs(tail: int = 150):
    state = APP_STATE
    try:
        with open(state.log_path, "r", encoding="utf-8", errors="replace") as fh:
            lines = [ln.rstrip("\n") for ln in fh][-max(1, min(tail, 500)):]
        return models.LogResponse(lines=lines)
    except FileNotFoundError:
        return models.LogResponse(lines=[])
    except Exception as exc:
        raise HTTPException(500, f"Could not read the log file: {exc}")


@app.websocket("/api/ws")
async def ws_endpoint(ws: WebSocket):
    """
    Live status channel. The server pushes a full snapshot on every monitor
    tick and immediately after block/unblock/master changes. Client messages
    are ignored (except an optional "refresh" request for a forced snapshot).
    Phones must present the passcode as ?pass=... or they only get a brief
    "passcode needed" signal and the socket closes.
    """
    class _WsProbe:
        """Lets the gate run against a WebSocket like a normal request."""
        def __init__(self, ws):
            self._ws = ws
            # covered by the same middleware logic through needs_pass()
            self.headers = ws.headers
            self.params = None
            self.qp = {}
            try:
                for k, v in ws.query_params.multi_items():
                    self.qp.setdefault(k, v)
            except Exception:
                self.qp = {}

        @property
        def client(self):
            return self._ws.client

        @property
        def query_params(self):
            return self.qp

        @property
        def headers(self):
            return self._hdrs

        @headers.setter
        def headers(self, value):
            self._hdrs = value

    probe = _WsProbe(ws)
    if needs_pass(probe):
        await ws.accept()
        await ws.send_text(json.dumps({"type": "gate_required"}))
        await ws.close(code=4401)
        return

    await manager.connect(ws)
    try:
        # hello snapshot
        await ws.send_text(json.dumps(snapshot(APP_STATE)))
        while True:
            msg = await ws.receive_text()
            if msg == "refresh":
                await ws.send_text(json.dumps(snapshot(APP_STATE)))
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        manager.disconnect(ws)


# ------------------------------ static files ----------------------------- #
# Mounted LAST so every /api/* route above keeps priority against "/"-mount.

FRONTEND_DIST = BASE_DIR.parent / "frontend" / "dist"
if FRONTEND_DIST.is_dir():
    app.mount(
        "/",
        StaticFiles(directory=str(FRONTEND_DIST), html=True),
        name="frontend",
    )
else:

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def _no_frontend() -> str:
        return (
            "<h2>NShield backend is running</h2>"
            "<p>The React frontend has not been built yet.</p>"
            "<p>Run <code>npm install &amp;&amp; npm run build</code> inside "
            "the <code>frontend/</code> folder, then restart the backend."
            "</p><p>API docs: <a href='/docs'>/docs</a></p>"
        )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def _confirm_allow_network(cidr: str) -> bool:
    msg = (
        "NetGuard detected a network it is not allowed to operate on:\\n\\n"
        "    " + cidr + "\\n\\n"
        "Allow NetGuard to manage THIS network?\\n\\n"
        "Only say Yes if this is YOUR network (your home/office Wi-Fi).\\n"
        "Using NetGuard on a network you do not own may be illegal."
    )
    if sys.platform == "win32":
        try:
            import ctypes
            MB_YESNO = 0x04
            MB_ICONQUESTION = 0x20
            MB_TOPMOST = 0x40000
            res = ctypes.windll.user32.MessageBoxW(
                None, msg, "NetGuard - new network detected",
                MB_YESNO | MB_ICONQUESTION | MB_TOPMOST,
            )
            return res == 6  # IDYES
        except Exception:
            pass
    try:
        if sys.stdin is not None and sys.stdin.isatty():
            ans = input("Allow NetGuard to manage " + cidr + "? [y/N] ").strip().lower()
            return ans in ("y", "yes")
    except Exception:
        pass
    return False


def _add_subnet_to_config(path: Path, cidr: str) -> None:
    try:
        text = path.read_text(encoding='utf-8')
    except FileNotFoundError:
        return
    lines = text.splitlines(keepends=True)
    idx = None
    for i, ln in enumerate(lines):
        if ln.strip().startswith('allowed_subnets:'):
            idx = i
            break
    if idx is None:
        if not text.endswith('\n'):
            lines.append('\n')
        lines.append('allowed_subnets:' + '\n')
        lines.append('  - "' + cidr + '"' + '\n')
        path.write_text(''.join(lines), encoding='utf-8')
        return
    j = idx + 1
    while j < len(lines) and lines[j].strip().startswith('- '):
        j += 1
    existing = [ln for ln in lines[idx + 1:j]]
    if any(cidr in ln for ln in existing):
        return
    lines.insert(j, '  - "' + cidr + '"' + '\n')
    path.write_text(''.join(lines), encoding='utf-8')

def refuse_startup(reason: str) -> None:
    def row(text: str) -> str:
        return '| ' + text.ljust(64) + ' |'

    box = '+' + '-' * 66 + '+'
    banner = [box]
    banner += [row('NShield REFUSED TO START'), row('')]
    banner += [row(reason[:64]), row('')]
    banner += [
        row('Edit backend/config.yaml and list the subnet(s) you own'),
        row('under allowed_subnets:, e.g.'),
        row(''),
        row('    allowed_subnets:'),
        row('      - "192.168.1.0/24"'),
        box,
    ]
    if sys.stderr is not None:
        sys.stderr.write(chr(10).join(banner) + chr(10))
    logger.critical(reason)
    sys.exit(1)


def uvicorn_log_config() -> dict:
    """
    Windowless-safe server logging. The default uvicorn logging config uses a
    colourized formatter that calls sys.stdout.isatty() - under pythonw.exe
    there is no stdout, so that raises before the server ever binds. Route the
    server's own messages into our root file log instead, with a plain
    NullHandler on the uvicorn logger so no StreamHandler is ever created.
    """
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "handlers": {"null": {"class": "logging.NullHandler"}},
        "loggers": {
            "uvicorn": {"handlers": ["null"], "propagate": True},
            # Per-request INFO lines would flood the action log; keep only
            # warnings and errors (e.g. bind failures) from uvicorn.access.
            "uvicorn.access": {"level": "WARNING"},
        },
    }


def main() -> None:
    global APP_STATE

    cfg = load_config()
    log_path = setup_logging(cfg)
    logger.info("Action log - %s", log_path)

    # 1. Detect local network first so the compliance check can use it.
    try:
        net = scanner.network_info()
    except Exception as exc:
        logger.critical("Interface detection failed: %s", exc)
        sys.exit(1)

    # 2. Auto-allow the current network so switching routers never blocks the app.
    #    Safety preserved: only private (RFC1918) LANs are auto-allowed; public
    #    IPs are still refused. Every auto-allow is appended to config.yaml and
    #    logged to data/auto_allowed.log for auditing.
    try:
        subnets = [
            ipaddress.ip_network(s, strict=False)
            for s in (cfg.get("allowed_subnets") or [])
        ]
    except ValueError as exc:
        refuse_startup(f"invalid allowed_subnets entry in config.yaml: {exc}")
    cidr = net.get("cidr") or (net["ip"].rsplit(".", 1)[0] + ".0/24")
    network = ipaddress.ip_network(cidr, strict=False)
    if not subnets or not scanner.is_ip_in_subnets(net["ip"], subnets):
        if not network.is_private:
            refuse_startup(
                f"local IP {net['ip']} is on a public network ({cidr}) - "
                f"NetGuard only runs on private LANs."
            )
        _add_subnet_to_config(BASE_DIR / "config.yaml", cidr)
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            with open(DATA_DIR / "auto_allowed.log", "a", encoding="utf-8") as fh:
                fh.write(
                    f"{time.strftime('%Y-%m-%d %H:%M:%S')}  auto-allowed {cidr} "
                    f"(local IP {net['ip']})\n"
                )
        except Exception:
            pass
        logger.warning(
            "AUTO-ALLOWED network %s (local IP %s). Review data/auto_allowed.log. "
            "Remove it from backend/config.yaml to revoke.", cidr, net["ip"],
        )
        cfg = load_config()
        subnets = [
            ipaddress.ip_network(s, strict=False)
            for s in (cfg.get("allowed_subnets") or [])
        ]
    logger.info("Compliance OK - %s inside %s", net["ip"], ", ".join(str(s) for s in subnets))

    privileged = is_privileged()
    APP_STATE = AppState(cfg, net, subnets, log_path, privileged)

    known_load()
    usage_load()
    # the app's own first status sweep makes every already-present device
    # "known" silently - real join alerts start ~45 s after launch
    global _alert_warmup_until
    _alert_warmup_until = time.time() + 45

    if privileged:
        # iface_obj is still inside `net` here; AppState pops it afterwards.
        install_static_gateway_arp(net, net.get("iface_obj"))
    else:
        logger.warning(
            "Skipping static gateway ARP (Administrator required): poison "
            "frames might affect this machine's own ARP cache."
        )

    atexit.register(shutdown_restore)

    # Hygiene: a previous run may have died with forwarding still on.
    if privileged:
        set_forwarding(APP_STATE, False, force=True)

    uvicorn.run(
        app,
        host="0.0.0.0",   # loopback always works; LAN needs phone access + the
                          # passcode (and Windows Firewall stays closed until
                          # phone access is switched on)
        port=int(cfg["server_port"]),
        log_level="warning",   # our own logging already covers request errors
        log_config=uvicorn_log_config(),
    )


if __name__ == "__main__":
    main()
