"""Metered-usage history for NShield.

Counting is only possible while a device is being watched (checkpoint mode -
its traffic passes through this PC), so the history covers exactly what was
metered. Stored per MAC, per day, in data/usage.json.
"""

import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
USAGE_PATH = DATA_DIR / "usage.json"

# Shared with main.py's logger (same name -> same logger instance).
import logging
logger = logging.getLogger("nshield")

_usage_lock = threading.RLock()
USAGE: dict = {"days": {}}          # "YYYY-MM-DD" -> mac -> {"up": int, "down": int}
_usage_last_save = 0.0
USAGE_KEEP_DAYS = 120


def _usage_day() -> str:
    return datetime.now().astimezone().date().isoformat()


def usage_load() -> None:
    with _usage_lock:
        try:
            with open(USAGE_PATH, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict) and isinstance(raw.get("days"), dict):
                USAGE["days"] = raw["days"]
        except FileNotFoundError:
            pass
        except Exception as exc:
            logger.warning("usage.json unreadable (%s) - starting fresh", exc)


def usage_save() -> None:
    global _usage_last_save
    with _usage_lock:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            tmp = USAGE_PATH.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(USAGE, fh)
            os.replace(tmp, USAGE_PATH)
            _usage_last_save = time.time()
        except Exception as exc:
            logger.warning("usage.json could not be saved: %s", exc)


def usage_prune() -> None:
    """Drop the dusty bottom of the history (older than ~4 months)."""
    with _usage_lock:
        days = USAGE["days"]
        cutoff = (datetime.now().astimezone().date() -
                  timedelta(days=USAGE_KEEP_DAYS)).isoformat()
        for day in [d for d in days if d < cutoff]:
            del days[day]


def usage_add(mac_l: str, up: int, down: int, day: Optional[str] = None) -> None:
    with _usage_lock:
        day = day or _usage_day()
        entry = USAGE["days"].setdefault(day, {}).setdefault(
            mac_l, {"up": 0, "down": 0})
        entry["up"] += int(up)
        entry["down"] += int(down)
        global _usage_last_save
        if time.time() - _usage_last_save > 15:
            usage_prune()
            usage_save()


def usage_totals(mac_l: str, day: Optional[str] = None,
                 month_from: Optional[str] = None) -> Tuple[int, int]:
    """(up, down) bytes for one day (or since month_from, day omitted)."""
    with _usage_lock:
        up = down = 0
        for d, devs in USAGE["days"].items():
            m = devs.get(mac_l)
            if m is None:
                continue
            chosen = d == day if day else (d >= (month_from or ""))
            if chosen:
                up += int(m.get("up", 0))
                down += int(m.get("down", 0))
        return up, down


def usage_flush_flow(state, ip: str, flow: dict) -> None:
    """Commit a watched device's un-committed session bytes into history."""
    try:
        up_c = int(flow.get("up_c") or 0)
        down_c = int(flow.get("down_c") or 0)
        up, down = int(flow.get("up") or 0), int(flow.get("down") or 0)
        if up == up_c and down == down_c:
            return                      # nothing new to book
        mac_l = (state.devices.get(ip, {}).get("mac") or "").lower()
        if mac_l:
            usage_add(mac_l, max(0, up - up_c), max(0, down - down_c))
        flow["up_c"], flow["down_c"] = up, down
    except Exception:
        pass


def _month_start() -> str:
    d = datetime.now().astimezone().date()
    return d.replace(day=1).isoformat()


__all__ = [
    "DATA_DIR", "USAGE_PATH", "_usage_lock", "USAGE", "_usage_last_save",
    "USAGE_KEEP_DAYS", "_usage_day", "usage_load", "usage_save", "usage_prune",
    "usage_add", "usage_totals", "usage_flush_flow", "_month_start",
]
