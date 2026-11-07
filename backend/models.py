"""
NetGuard — Pydantic models shared by the REST API and WebSocket payloads.
"""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class NetworkInfo(BaseModel):
    """Everything the backend knows about the local machine and network."""
    ip: str
    mac: str
    netmask: str
    cidr: str                              # e.g. "192.168.1.0/24"
    gateway_ip: str
    gateway_mac: Optional[str] = None
    iface: str                             # scapy/Npcap interface id
    iface_friendly: str                    # "Wi-Fi" / "eth0" style human name
    privileged: bool = False               # running as Administrator/root?


class Device(BaseModel):
    ip: str
    mac: str
    hostname: str = ""
    vendor: str = ""
    online: bool = False
    blocked: bool = False
    watched: bool = False                  # usage metering active (checkpoint mode)
    down_rate: float = 0.0                 # bytes/s download EMA
    up_rate: float = 0.0                   # bytes/s upload EMA
    total_down: int = 0                    # bytes down since watching started
    total_up: int = 0                      # bytes up since watching started
    cap_down_kbps: Optional[int] = None    # download cap in KB/s (None = no limit)
    cap_up_kbps: Optional[int] = None      # upload cap in KB/s (None = no limit)
    custom_name: Optional[str] = None      # friendly name the user gave it
    icon: Optional[str] = None             # chosen device icon id (lucide set)
    auto_name: Optional[str] = None        # name the network itself announced
    auto_icon: Optional[str] = None        # icon guessed from network hints
    quota_mb: Optional[int] = None         # daily data budget (MB), per MAC
    used_today: float = 0.0                # bytes used today (metered devices)
    used_month: float = 0.0                # bytes used this month (metered)
    watched_since: Optional[str] = None    # ISO-8601 when metering started
    last_seen: Optional[str] = None       # ISO-8601 local timestamp (sniffer/monitor)
    last_poisoned: Optional[str] = None   # ISO-8601 of the last sent poison burst


class BlockRequest(BaseModel):
    ip: str = Field(..., description="IP of the device to block or unblock")


class WatchRequest(BaseModel):
    ip: str = Field(..., description="IP of the device to watch or unwatch")
    enabled: bool


class CapRequest(BaseModel):
    ip: str = Field(..., description="IP of the watched device to cap")
    down_kbps: Optional[int] = Field(None, description="download cap KB/s; 0/None = no limit")
    up_kbps: Optional[int] = Field(None, description="upload cap KB/s; 0/None = no limit")
    quota_mb: Optional[int] = Field(
        None, ge=0, le=1024 * 1024,
        description="daily data budget MB; 0/None removes it",
    )


class MasterRequest(BaseModel):
    enabled: bool


class DeviceListResponse(BaseModel):
    devices: List[Device]
    master: bool


class ScanResponse(BaseModel):
    devices: List[Device]
    scanned_cidr: str


class ActionResponse(BaseModel):
    ok: bool
    message: str = ""


class LogResponse(BaseModel):
    lines: List[str]


class RenameRequest(BaseModel):
    """Give a device a friendly name (and optional icon), remembered by MAC."""
    mac: str = Field(..., description="MAC address of the device to rename")
    name: str = Field("", max_length=28, description="friendly name; empty clears it")
    icon: str = Field("", max_length=24, description="icon id from the icon list")


class GateResponse(BaseModel):
    """Phone-access gate: does this client need to enter the passcode?"""
    needed: bool


class SettingsResponse(BaseModel):
    phone_access: bool
    passcode: str
    lan_url: str = ""             # full address for the phone, e.g. http://192.168.1.13:8000
    alerts_on: bool
    autostart: bool


class SettingsUpdate(BaseModel):
    """Partial updates - only set the fields you want to change."""
    phone_access: Optional[bool] = None
    passcode: Optional[str] = Field(None, min_length=4, max_length=12)
    alerts_on: Optional[bool] = None
    autostart: Optional[bool] = None
