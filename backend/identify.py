"""
NetGuard - automatic device identification.

Devices tell the network what they are, in three "voices":

  * DHCP hostname     - computers/phones register a name when joining
  * mDNS broadcasts   - Apple TV ("Living Room"), Chromecast, printers,
                        AirPlay speakers, phones/tablets announce names
                        and service kinds continuously on UDP 5353
  * SSDP (UPnP)       - smart TVs, consoles and set-top boxes advertise
                        on UDP 1900
  * MAC vendor (OUI)  - who made the device

`suggest()` turns all of that into a friendly display name + an icon id.
Names/icons the user sets by hand always win over our suggestions.
"""
from __future__ import annotations

import re
from typing import Dict, Optional, Tuple

from scapy.all import Ether, IP, IPv6, UDP

# ---- icon ids must stay in sync with ALLOWED_ICONS in main.py --------------

SERVICE_ICON: Dict[str, str] = {
    "airplay": "tv",                 # AirPlay video target: Apple TV / smart TV
    "raop": "speaker",               # AirPlay audio receiver
    "googlecast": "tv",              # Chromecast / Google TV
    "spotify-connect": "speaker",
    "ipp": "printer",
    "ipps": "printer",
    "pdl-datastream": "printer",
    "printer": "printer",
    "scanner": "printer",
    "uscan": "printer",
    "usps": "printer",
    "sonos": "speaker",
    "homepod": "speaker",
}

ICON_RANK = {
    "tv": 6, "gamepad": 5, "printer": 4, "speaker": 3,
    "phone": 3, "tablet": 3, "laptop": 3, "desktop": 3,
    "router": 2, "watch": 2,
}

# Ordered hostname patterns: first hit wins where ranks tie.
HOST_PATTERNS = [
    (r"android-?tv|google-?tv|fire[- ]?tv|firetv|bravia|webos|tizen|"
     r"smart-?tv|chromecast|shield-?android|apple[ -]?tv|now-?tv|"
     r"(^|[^a-z0-9])tv([^a-z0-9]|$)", "tv"),
    (r"playstation|\bps[345]\b|xbox|nintendo|wiiu", "gamepad"),
    (r"iphone", "phone"),
    (r"\bipad\b", "tablet"),
    (r"mac[- ]?book", "laptop"),
    (r"imac|mac[- ]?mini|macintosh|mac[- ]?pro|desktop-", "desktop"),
    (r"hp[a-f0-9]{4,}|epson|pixma|laserjet|\bprint|brother", "printer"),
    (r"echo|alexa|homepod|nest[- ]?(audio|mini|hub|show)|sonos", "speaker"),
    (r"router|gateway|openwrt|fritz|archer|orbi|eero|unifi|keenetic", "router"),
    (r"apple[ -]?watch|\bwatch\b", "watch"),
    (r"android|oneplus|xiaomi|redmi|pixel|\boppo\b|\bvivo\b|huawei|honour|harmony", "phone"),
]

# SSDP SERVER/NT strings (smart TVs love shouting model names here).
SSDP_PATTERNS = [
    (r"smarttv|smart[ -]?tv|bravia|webos|viera|tizen|mediarenderer|"
     r"samsung\s*tv|lg\s*tv|sony\s*tv|android\s*tv|tv\s*remote|"
     r"digibox|freesat|sagemcom|humax", "tv"),
    (r"playstation|ps[45]|xbox", "gamepad"),
    (r"sonos", "speaker"),
]

VENDOR_PATTERNS = [
    (r"sonos", "speaker"),
    (r"nintendo", "gamepad"),
    (r"bose|sennheiser|jbl|beats|harman", "headphones"),
    (r"vestel|skyworth|hisense|loewe|bouygues", "tv"),
    (r"\bepson\b|\bricoh\b|\bxerox\b|\bcanon\b", "printer"),
]

_HOST_RE = [(re.compile(pat, re.I), icon) for pat, icon in HOST_PATTERNS]
_SSDP_RE = [(re.compile(pat, re.I), icon) for pat, icon in SSDP_PATTERNS]
_VENDOR_RE = [(re.compile(pat, re.I), icon) for pat, icon in VENDOR_PATTERNS]

_RAOP_MAC_RE = re.compile(r"^[0-9a-fA-F]{9,12}@")   # raop names start "<mac>@Living Room"

# Search-list of borrowed keywords -> regex to icon (reuse host table)
_KEYWORD_ICON = {
    "tv": "tv", "chromecast": "tv", "airplay": "tv", "apple tv": "tv",
    "gamepad": "gamepad", "printer": "printer", "speaker": "speaker",
    "phone": "phone", "tablet": "tablet", "laptop": "laptop",
    "desktop": "desktop", "router": "router", "watch": "watch",
    "headphones": "headphones",
}


SERVICE_ICON["nearbypresence"] = "phone"     # phones' "nearby devices" feature

# Broadcast labels that are features, not devices - never show as a name.
_FEATURE_NOISE_RE = re.compile(
    r"^(nearby\s*presence|nearbypresence|nearby|presence|companion|"
    r"sleep\s*proxy|media\s*renderer|media\s*server|root\s*device)$", re.I)


def suggest(vendor: str = "", hostname: str = "",
            hints: Optional[dict] = None) -> Tuple[str, str]:
    """(friendly_name_or_empty, icon) from everything the network knows."""
    hints = hints or {}

    # ---- display name from the broadcast itself, when it is a real one ---- #
    name = ""
    instance = (hints.get("instance") or "").strip().strip('"')
    if (
        instance
        and instance.lower() != str(hostname or "").lower()
        and not _FEATURE_NOISE_RE.match(instance)
    ):
        name = _RAOP_MAC_RE.sub("", instance)[:28].strip()
        if _FEATURE_NOISE_RE.match(name):   # "<mac-id>@NearbyPresence" etc.
            name = ""

    # ---- icon: strongest evidence wins ------------------------------- ---- #
    candidates: Dict[str, int] = {}          # icon -> best rank seen

    def add(icon: str, rank: int) -> None:
        if icon:
            candidates[icon] = max(candidates.get(icon, 0), rank)

    # explicit service kinds from mDNS/SSDP count most
    for svc in hints.get("services") or ():
        add(SERVICE_ICON.get((svc or "").lower(), ""), 8)

    blob = " ".join(
        (hints.get("instance") or "", hints.get("server") or "",
         hostname or "", vendor or "")
    ).lower()
    for regex, icon in _SSDP_RE:
        if regex.search(blob):
            add(icon, 6)
    for regex, icon in _HOST_RE:
        if hostname and regex.search(str(hostname)):
            add(icon, 5)
    for regex, icon in _VENDOR_RE:
        if vendor and regex.search(str(vendor)):
            add(icon, 4)

    best_icon = max(candidates.items(), key=lambda kv: kv[1])[0] if candidates else ""
    if not best_icon and not name:
        return "", ""
    return name, best_icon


# --------------------------------------------------------------------------- #
# Light Nmap-style probe: read the small web page most devices serve
# (their "remote control" page). Windows/phones usually show nothing;
# TVs, printers, NAS and routers tell what they are in the title/banners.
# --------------------------------------------------------------------------- #

WEB_PORTS = (80, 5000, 55000, 8080, 9000)
_PORT_HINTS = {
    5000: "samsung tv",           # Samsung TV remote control port
    55000: "lg smart tv",         # LG WebOS remote port
    9197: "mediarenderer",        # DLNA renderers
}


def web_probe(ip: str, mac: str) -> Optional[dict]:
    """Headers/title of the first answering web port, else None."""
    import socket
    for port in WEB_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4)
        try:
            s.connect((ip, port))
        except Exception:
            s.close()
            continue
        try:
            s.settimeout(1.2)
            s.sendall(
                f"GET / HTTP/1.0\r\nHost: {ip}\r\n"
                f"User-Agent: Mozilla/5.0 (NetGuard)\r\n\r\n".encode())
            chunks = b""
            while len(chunks) < 4096:
                part = s.recv(2048)
                if not part:
                    break
                chunks += part
        except Exception:
            pass
        finally:
            s.close()
        text = chunks.decode("utf-8", "replace")
        server = ""
        title = ""
        if "\r\n\r\n" in text:
            head, _, body = text.partition("\r\n\r\n")
        else:
            head, body = text, ""
        for line in head.splitlines():
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
        low = body.lower()
        if "<title>" in low:
            base = low.find("<title>")
            start, stop = base + len("<title>"), low.find("</title>", base)
            if stop > start:
                title = body[start:stop].strip()[:60]
        hint = _PORT_HINTS.get(port, "")
        if not (server or title or hint):
            continue
        return {
            "mac": mac,
            "ip": ip,
            "services": [],
            "instance": title,
            "hostname": "",
            "server": f"{server} {hint}".strip(),
            "source": "web",
        }
    return None


# --------------------------------------------------------------------------- #
# Live packet parsing (called from the sniffing thread)
# --------------------------------------------------------------------------- #

def _rr_name_str(rrname) -> str:
    if isinstance(rrname, (bytes, bytearray)):
        try:
            rrname = rrname.decode("utf-8", "replace")
        except Exception:
            rrname = str(rrname)
    s = str(rrname)
    return s[:-1] if s.endswith(".") else s


def parse_mdns(pkt) -> Optional[dict]:
    """Extract (mac, ip, hints) from an mDNS announcement, or None."""
    try:
        udp = pkt[UDP]
        if udp.dport != 5353 and udp.sport != 5353:
            return None
        from scapy.all import DNS, DNSRR
        if not pkt.haslayer(DNS):
            return None
        mac = str(pkt[Ether].src).lower()
        if pkt.haslayer(IP):
            ip = str(pkt[IP].src)
        elif pkt.haslayer(IPv6):
            ip = str(pkt[IPv6].src)
        else:
            return None
        if not mac or not ip:
            return None

        services: set = set()
        instance = ""
        hostname = ""
        dns = pkt[DNS]
        for kind in ("an", "ns", "ar"):
            section = None
            try:
                section = getattr(dns, kind)
            except Exception:
                section = None
            if not section:
                continue
            try:
                records = section
                count = int(getattr(dns, kind + "count", 0) or 0)
                for i in range(count):
                    rr = records[i]
                    name = _rr_name_str(rr.rrname)
                    parts = name.split("._")
                    if len(parts) >= 2:
                        instance = instance or parts[0]
                        services.add(parts[1].split(".")[0].strip().lower())
                    elif name.lower().endswith(".local") and rr.type == 1:
                        hostname = hostname or name[:-len(".local")]
            except Exception:
                continue
        if not services and not instance:
            return None
        return {
            "mac": mac,
            "ip": ip,
            "services": sorted(services),
            "instance": _RAOP_MAC_RE.sub("", instance).strip(),
            "hostname": hostname,
            "source": "mdns",
        }
    except Exception:
        return None


def parse_ssdp(pkt) -> Optional[dict]:
    """Extract (mac, ip, hints) from an SSDP/UPnP announcement, or None."""
    try:
        udp = pkt[UDP]
        if udp.dport != 1900 and udp.sport != 1900:
            return None
        mac = str(pkt[Ether].src).lower()
        if pkt.haslayer(IP):
            ip = str(pkt[IP].src)
        elif pkt.haslayer(IPv6):
            ip = str(pkt[IPv6].src)
        else:
            return None
        payload = bytes(pkt[UDP].payload)
        try:
            text = payload.decode("utf-8", "replace")
        except Exception:
            return None
        services: set = set()
        server = ""
        nt_kind = ""
        for line in text.splitlines():
            line = line.strip()
            low = line.lower()
            if low.startswith(("nt:", "st:")):
                nt_kind = line.split(":", 1)[1].strip()
                if "mediarenderer" in nt_kind.lower():
                    services.add("mediarenderer")
                elif "mediaserver" in nt_kind.lower():
                    services.add("mediaserver")
            elif low.startswith("server:"):
                server = line.split(":", 1)[1].strip()[:120]
        if not server and not nt_kind:
            return None
        return {
            "mac": mac,
            "ip": ip,
            "services": sorted(services),
            "instance": "",
            "hostname": "",
            "server": f"{server} {nt_kind}".strip(),
            "source": "ssdp",
        }
    except Exception:
        return None


# Explicit "mediarenderer/mediaserver" services were decoded above so that
# suggest() sees real keywords instead of service ids.
def _patched_service_icon() -> None:
    SERVICE_ICON.setdefault("mediarenderer", "tv")
    SERVICE_ICON.setdefault("mediaserver", "tv")


_patchd = None  # marker kept intentionally small
if _patchd is None:
    _patched_service_icon()
    _patchd = True
