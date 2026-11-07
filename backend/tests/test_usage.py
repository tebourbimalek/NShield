"""Tests for the metered-usage store, quotas and CSV export.

These run against an in-memory fake AppState so no network, admin rights or
scapy are needed. The point is to lock down the accounting logic that the UI
and the auto-cutoff rely on.
"""

import ipaddress
import io
import csv
import time
import threading
from collections import OrderedDict

import pytest

import main as m
from main import models


@pytest.fixture
def state():
    """A fresh, isolated AppState + stores for each test."""
    st = object.__new__(m.AppState)
    st.lock = threading.RLock()
    st.devices = OrderedDict()
    st.watched = set()
    st.traffic = {}
    st.subnets = [ipaddress.ip_network("192.168.1.0/24")]
    st.net = {
        "ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:ff",
        "gateway_ip": "192.168.1.1", "gateway_mac": "00:11:22:33:44:66",
        "iface_friendly": "Wi-Fi", "iface": "x", "cidr": "192.168.1.0/24",
        "privileged": True,
    }
    st.master = True
    st.compliant = True
    st.cfg = {"server_port": 8000}
    st.loop = None
    st.iface_obj = "IFACE"
    st.privileged = True
    st.stop_evt = threading.Event()
    st.forwarding_on = False

    blocks = []
    class FakeEngine:
        def block(self, *a, **k):
            blocks.append(a)
            return None
        def unblock(self, ip):
            return True
        def stop_all(self, restore=True):
            return 0
        def count(self):
            return 0
    st.engine = FakeEngine()
    st._blocks = blocks
    st.ensure_router_ll = lambda: None

    m.APP_STATE = st
    news = []
    st.push_event = lambda d: news.append(d)
    st._news = news
    notify = []
    m.windows_notify = lambda t, x: notify.append(x)
    st._notify = notify
    m.qos_clear_cap = lambda *a, **k: None

    m.KNOWN = {
        "names": {}, "ack_macs": {},
        "settings": {"phone": False, "passcode": None, "alerts": True},
        "quotas": {},
    }
    m.USAGE["days"].clear()
    return st


def _mk_device(state, ip="192.168.1.20", mac="AA:BB:CC:DD:EE:01"):
    rec = {"ip": ip, "mac": mac, "hostname": "", "vendor": "", "online": True,
           "blocked": False, "watched": True, "ts": time.time()}
    state.devices[ip] = rec
    state.watched.add(ip)
    flow = {
        "down": 0, "up": 0, "down_rate": 0.0, "up_rate": 0.0,
        "up_c": 0, "down_c": 0, "since": time.time(), "rate_ts": time.time(),
    }
    state.traffic[ip] = flow
    return ip, mac, flow


def test_usage_add_and_totals(state):
    m.usage_add("aa:bb:cc:dd:ee:01", 0, 1000)
    m.usage_add("aa:bb:cc:dd:ee:01", 0, 500)
    up, down = m.usage_totals("aa:bb:cc:dd:ee:01", day=m._usage_day())
    assert (up, down) == (0, 1500)


def test_flow_flush_books_session_bytes(state):
    ip, mac, flow = _mk_device(state)
    flow["down"] = 3000
    flow["up"] = 100
    m.usage_flush_flow(state, ip, flow)
    assert flow["up_c"] == 100 and flow["down_c"] == 3000
    up, down = m.usage_totals(mac.lower(), day=m._usage_day())
    assert (up, down) == (100, 3000)


def test_quota_overflow_cuts_device_off(state):
    ip, mac, flow = _mk_device(state)
    m.KNOWN["quotas"][mac.lower()] = 500  # MB scale, but test uses bytes accounting
    # push usage over a tiny budget by setting 1 MB quota
    m.KNOWN["quotas"][mac.lower()] = 0
    m.KNOWN["quotas"][mac.lower()] = 1
    m.usage_add(mac.lower(), 0, 2 * 1024 * 1024)
    state._news.clear()
    state._notify.clear()
    state._blocks.clear()
    m.quota_release_and_block(state, ip)
    assert ip not in state.watched
    assert state._blocks and state._blocks[0][0] == ip
    assert state.devices[ip]["blocked"] is True
    assert state._news and state._news[0]["type"] == "notice"
    assert state._notify


def test_month_totals_include_today(state):
    m.usage_add("aa:bb:cc:dd:ee:02", 100, 200)
    up, down = m.usage_totals("aa:bb:cc:dd:ee:02", month_from=m._month_start())
    assert (up, down) == (100, 200)


def test_device_model_exposes_budget_and_usage(state):
    ip, mac, flow = _mk_device(state)
    m.KNOWN["quotas"][mac.lower()] = 500
    flow["quota_mb"] = 500
    flow["used_today"] = 4500
    flow["used_month"] = 9000
    dm = m.device_model(state.devices[ip], state.traffic).model_dump()
    assert dm["quota_mb"] == 500
    assert dm["used_today"] >= 4500
    assert dm["watched"] is True


def test_cap_sets_and_clears_budget(state):
    ip, mac, flow = _mk_device(state)
    import asyncio
    r = asyncio.run(m.set_cap(models.CapRequest(ip=ip, quota_mb=800)))
    assert m.KNOWN["quotas"][mac.lower()] == 800
    r = asyncio.run(m.set_cap(models.CapRequest(ip=ip, quota_mb=0)))
    assert mac.lower() not in m.KNOWN["quotas"]


def test_usage_round_trip(state, tmp_path, monkeypatch):
    m.usage_add("aa:bb:cc:dd:ee:03", 5, 7)
    # redirect the store to a temp file
    monkeypatch.setattr(m, "USAGE_PATH", tmp_path / "usage.json")
    m.usage_save()
    m.USAGE["days"].clear()
    m.usage_load()
    up, down = m.usage_totals("aa:bb:cc:dd:ee:03", day=m._usage_day())
    assert (up, down) == (5, 7)


def test_export_csv_contents(state):
    m.usage_add("aa:bb:cc:dd:ee:04", 100, 200 * 1024 * 1024)
    resp = m.export_usage(days=7)
    body = resp.body.decode("utf-8")
    rows = list(csv.reader(io.StringIO(body)))
    assert rows[0] == ["date", "name", "ip", "mac", "uploaded_mb", "downloaded_mb"]
    big = [r for r in rows[1:] if r[3] == "aa:bb:cc:dd:ee:04"]
    assert big and big[0][0] == m._usage_day()
    assert float(big[0][5]) == 200.0


def test_old_history_pruned(state):
    m.USAGE["days"]["2020-01-01"] = {"aa:bb:cc:dd:ee:05": {"up": 1, "down": 1}}
    m.usage_prune()
    assert "2020-01-01" not in m.USAGE["days"]
