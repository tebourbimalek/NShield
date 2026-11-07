"""
NetGuard — network discovery and host liveness via ARP (scapy).

Everything in here is pure ARP/DNS + passive sniffing, no TCP traffic.
All srp()/sniff() calls take an explicit iface so NetGuard always uses the
interface detected at startup.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from typing import Callable, Dict, Iterable, List, Optional

import identify

from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    Ether,
    IP,
    IPv6,
    ICMPv6ND_RA,
    ICMPv6ND_RS,
    UDP,
    conf,
    get_if_addr,
    get_if_hwaddr,
    sendp,
    sniff,
    srp,
)

logger = logging.getLogger("netguard.scanner")

# --------------------------------------------------------------------------- #
# Best-effort OUI vendor table (first three MAC octets).
# For the full database `pip install manuf` — VendorLookup picks it up
# automatically when present.
# --------------------------------------------------------------------------- #
COMMON_OUI: Dict[str, str] = {
    # Virtual machines / hypervisors (very common in a home lab)
    "00:0C:29": "VMware", "00:05:69": "VMware", "00:1C:14": "VMware",
    "00:50:56": "VMware", "08:00:27": "Oracle VirtualBox",
    "00:1C:42": "Parallels Desktop", "52:54:00": "QEMU/KVM",
    "00:15:5D": "Microsoft Hyper-V", "00:16:3E": "Xen",
    # Consumer / PC vendors
    "00:1B:63": "Apple", "00:1E:C2": "Apple", "00:17:F2": "Apple",
    "00:16:CB": "Apple", "3C:22:FB": "Apple",
    "00:16:32": "Samsung", "8C:77:12": "Samsung", "C4:57:6E": "Samsung",
    "00:14:22": "Dell", "18:03:73": "Dell", "D4:BE:D9": "Dell",
    "00:1F:29": "HP", "3C:D9:2B": "HP",
    "00:1B:21": "Intel", "00:1D:E0": "Intel", "00:1F:CA": "Intel",
    "00:24:D6": "Intel", "3C:A9:F4": "Intel", "A0:88:B4": "Intel",
    "00:E0:4C": "Realtek",
    # Routers / infrastructure
    "00:09:5B": "NETGEAR", "00:1B:2F": "NETGEAR", "20:4E:16": "NETGEAR",
    "14:CC:20": "TP-Link", "24:69:68": "TP-Link", "98:DA:C4": "TP-Link",
    "00:1A:11": "Google", "3C:5A:B4": "Google", "F4:F5:D8": "Google",
    # Single-board computers
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
}


class VendorLookup:
    """MAC OUI -> vendor name, with a process-wide result cache."""

    def __init__(self) -> None:
        self._cache: Dict[str, str] = {}
        self._manuf = None
        try:
            from manuf import manuf as manuf_mod  # optional dependency
            self._manuf = manuf_mod.MacParser()
            logger.info("OUI vendor DB: full database loaded from 'manuf' package")
        except Exception:
            logger.info("OUI vendor DB: using built-in table (install 'manuf' for full coverage)")

    def lookup(self, mac: str) -> str:
        if not mac:
            return ""
        key = mac.upper().replace("-", ":")[:8]            # "AA:BB:CC"
        if key in self._cache:
            return self._cache[key]
        vendor = ""
        if self._manuf is not None:
            try:
                record = self._manuf.get_manuf(mac)
                if record:
                    # Different manuf versions expose different attributes
                    for attr in ("manuf_long", "manuf_long_name", "manuf"):
                        val = getattr(record, attr, None)
                        if val:
                            vendor = str(val).strip()
                            break
            except Exception:
                pass
        if not vendor:
            vendor = COMMON_OUI.get(key, "")
        self._cache[key] = vendor
        return vendor


# Process-wide singleton, used by scanner + main.
vendor_lookup = VendorLookup()


# --------------------------------------------------------------------------- #
# Passive IPv6 address learning (NDP Snooping - "who is this MAC in IPv6?")
#
# NDP has no broadcast query like ARP: on-link addresses become visible
# through Neighbor Solicitations / Advertisements and ordinary IPv6 frames.
# The spoof engine needs every IPv6 address of a target (link-local +
# globals) to poison the router's neighbor cache, so we keep a MAC-keyed
# registry updated from the same passive sniffer that watches IPv4.
# --------------------------------------------------------------------------- #

_ipv6_lock = threading.Lock()
_ipv6_hosts: Dict[str, dict] = {}      # mac -> {"ll": ..., "globals": set, "ts": ...}
MAX_V6_GLOBALS = 8                     # bound memory against privacy/spoofed floods


def _remember_ipv6(mac: str, v6: str, link_local: bool) -> None:
    mac_l = (mac or "").lower()
    v6 = (v6 or "").lower()
    if not mac_l or not v6 or v6.startswith("ff"):
        return
    with _ipv6_lock:
        rec = _ipv6_hosts.setdefault(
            mac_l, {"ll": None, "globals": set(), "ts": 0.0}
        )
        if link_local:
            rec["ll"] = v6
        elif len(rec["globals"]) < MAX_V6_GLOBALS:
            rec["globals"].add(v6)
        rec["ts"] = time.time()


def ipv6_profile(mac: str) -> dict:
    """All IPv6 addresses learned for a MAC: {"ll": str|None, "globals": [..]}."""
    mac_l = (mac or "").lower()
    with _ipv6_lock:
        rec = _ipv6_hosts.get(mac_l)
        if not rec:
            return {"ll": None, "globals": []}
        return {"ll": rec["ll"], "globals": sorted(rec["globals"])}


# --------------------------------------------------------------------------- #
# Network discovery
# --------------------------------------------------------------------------- #

def _src_mac_for_iface(iface) -> Optional[str]:
    """
    MAC of the outgoing interface, so crafted frames carry an explicit
    Ether(src=...). Without it, scapy resolves the source MAC through its
    route cache at build time, which misbehaves on some Windows hosts
    (virtual adapters / driver pseudo-interfaces are not always registered).
    """
    mac = getattr(iface, "mac", None)
    if not mac:
        try:
            mac = get_if_hwaddr(str(iface))
        except Exception:
            mac = None
    return mac


def _arp_probe(pdst: str, iface):
    """
    Fully-explicit broadcast ARP who-has probe.

    Every field (Ether.src, ARP.psrc, ARP.hwsrc, ARP.hwdst) is set manually:
    scapy would otherwise auto-resolve unset fields through its route cache at
    build time, which crashes on some Windows hosts whose virtual/pseudo
    adapters (KM-TEST etc.) are not in the pcap interface registry.
    """
    our_mac = _src_mac_for_iface(iface)
    our_ip = getattr(iface, "ip", None) or get_if_addr(str(iface))
    return Ether(src=our_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,                       # who-has
        pdst=pdst,                  # we ask about this
        psrc=our_ip,                # sender's IP (ours)
        hwsrc=our_mac,              # sender's MAC (ours)
        hwdst="00:00:00:00:00:00",  # unknown target, standard for who-has
    )


def quick_route() -> Tuple[str, str, str]:
    """
    Cheap default-route snapshot WITHOUT any packets: (iface_name, out_ip,
    gateway_ip) straight from scapy's (cached) route table. Used by the
    monitor loop to watch for interface/subnet changes between cycles.
    """
    try:
        route_tuple = conf.route.route("0.0.0.0")
        return str(route_tuple[0]), route_tuple[1] or "", route_tuple[2] or ""
    except Exception:
        return "", "", ""


def router_link_local(iface, gateway_mac: str, timeout: float = 4.0) -> Optional[str]:
    """
    Discover the router's IPv6 link-local address.

    Primary source: scapy's IPv6 route table - the default route's next hop
    IS the router's link-local (zero packets, instant). Fallback: send a
    Router Solicitation (fully explicit fields, unspecified source is legal
    for RS) and read the source of the resulting Router Advertisement.
    """
    ifaces6 = set()
    try:
        for row in conf.route6.routes:
            ifaces6.add(str(row[3]))
    except Exception:
        pass
    try:
        route6 = conf.route6.route("::/0")   # -> (iface, out_ip, gateway)
        gateway6 = str(route6[2] or "")
        if gateway6.lower().startswith("fe80") and str(route6[0]) == str(iface):
            _remember_ipv6(gateway_mac, gateway6, True)
            return gateway6
    except Exception:
        gateway6 = ""
    if gateway6.lower().startswith("fe80") and not ifaces6:
        return gateway6
    our_mac = _src_mac_for_iface(iface)
    rs = Ether(src=our_mac, dst="33:33:00:00:00:02") / IPv6(
        src="::", dst="ff02::2", hlim=255, nh=58
    ) / ICMPv6ND_RS()
    gw_l = (gateway_mac or "").lower()
    end = time.time() + max(1.0, timeout)
    while time.time() < end:
        try:
            sendp(rs, iface=iface, verbose=0)
            remaining = max(0.3, min(1.5, end - time.time()))
            pkts = sniff(
                iface=iface,
                filter="icmp6",
                timeout=remaining,
                store=False,
                lfilter=lambda p: ICMPv6ND_RA in p,
            )
            for pkt in pkts:
                eth = str(pkt[Ether].src).lower()
                src = str(pkt[IPv6].src)
                if not src.lower().startswith("fe80"):
                    continue
                if gw_l and eth != gw_l:
                    continue
                _remember_ipv6(eth, src, True)      # announces the router MAC too
                return src
        except Exception as exc:
            logger.warning("Router solicitation failed: %s", exc)
            time.sleep(0.5)
    return None


def arp_query_single(ip: str, iface, timeout: float = 2.0) -> Optional[str]:
    """Unicast-target ARP request. Returns the answering MAC or None."""
    ans, _ = srp(
        _arp_probe(ip, iface),
        iface=iface,
        timeout=timeout,
        verbose=0,
    )
    for _sent, received in ans:
        if received.haslayer(ARP) and received[ARP].hwsrc:
            return received[ARP].hwsrc
    return None


def arp_ping_subnet(cidr: str, iface, timeout: float = 2.0) -> Dict[str, str]:
    """
    One broadcast ARP ping across `cidr`.
    Returns {ip: MAC} for every host that answered.
    """
    ans, _ = srp(
        _arp_probe(cidr, iface),
        iface=iface,
        timeout=timeout,
        verbose=0,
    )
    hosts: Dict[str, str] = {}
    for _sent, received in ans:
        if received.haslayer(ARP):
            ip, mac = received[ARP].psrc, received[ARP].hwsrc
            if ip and mac and ip != "0.0.0.0":
                hosts[ip] = mac
    return hosts


def arp_is_alive(ip: str, iface, timeout: float = 0.5) -> bool:
    """Direct ARP ping of a single host (cheap liveness probe)."""
    ans, _ = srp(
        _arp_probe(ip, iface),
        iface=iface,
        timeout=timeout,
        verbose=0,
    )
    return len(ans) > 0


def _hostname_of(ip: str) -> str:
    """Reverse-DNS one IP; returns the short hostname or ''."""
    try:
        host = socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    if not host:
        return ""
    # Prefer the short hostname ("nas" over "nas.local")
    return host.split(".")[0] or host


def resolve_hostnames(
    ips: Iterable[str],
    deadline: float = 4.0,
    max_workers: int = 16,
) -> Dict[str, str]:
    """
    Reverse-DNS / mDNS hostname resolution with a hard overall deadline, so a
    misbehaving resolver can never stall a scan. Hostnames that do not resolve
    in time come back as "".

    Concurrency design (deliberately NOT ThreadPoolExecutor):
    since Python 3.9, ThreadPoolExecutor worker threads are non-daemon and are
    joined at interpreter exit. A resolver wedged in an exec-internal
    gethostbyaddr() call would, therefore, become "orphaned work" that blocks
    process shutdown for as long as the OS resolver hangs. Instead, we spawn
    plain daemon threads with a bounded semaphore:

      * at most `max_workers` threads are actually inside the OS resolver at
        the same time (bounded concurrency, like a bounded pool),
      * the caller waits at most `deadline` seconds in total and abandons
        stragglers (their results are then ignored),
      * stragglers are daemon threads, so whatever the OS resolver does, they
        can never delay NetGuard's process exit.
    """
    out: Dict[str, str] = {}
    unique = list(dict.fromkeys(ips))
    if not unique:
        return out

    semaphore = threading.Semaphore(max_workers)
    lock = threading.Lock()
    results: Dict[str, str] = {}

    def _worker(ip: str) -> None:
        semaphore.acquire()
        try:
            hostname = _hostname_of(ip)
        except Exception:
            hostname = ""
        finally:
            with lock:
                results[ip] = hostname
            semaphore.release()

    threads: List[threading.Thread] = []
    for ip in unique:
        thread = threading.Thread(
            target=_worker, args=(ip,), name="netguard-dns", daemon=True
        )
        thread.start()
        threads.append(thread)

    end = time.time() + max(0.0, deadline)
    for thread in threads:
        remaining = end - time.time()
        if remaining <= 0:
            break  # everything past the deadline is abandoned, results default ""
        thread.join(timeout=remaining)

    for ip in unique:
        with lock:
            out[ip] = results.get(ip, "")
    return out


def is_ip_in_subnets(ip: str, subnets: Iterable["ipaddress.IPv4Network"]) -> bool:
    """Guardrail helper: strict membership check against the allow-listed subnets."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in subnets)


def iface_display_name(iface) -> str:
    """Human-readable interface name; str() on Windows is the raw GUID."""
    return (
        getattr(iface, "friendly_name", None)
        or getattr(iface, "name", None)
        or str(iface)
    )


def network_info() -> dict:
    """
    Detect the default gateway, local interface, IP, MAC and subnet.

    We deliberately pick the *interface that owns the default route* instead
    of blindly trusting conf.iface: on hosts with several NICs (VMware, WSL,
    Docker...) scapy's default interface and the default route often
    disagree, which would report a gateway that is not on that subnet.
    If no netmask can be resolved we default to /24 (the overwhelmingly
    common home-lab layout) — adjust config.yaml for exotic setups.
    """
    iface_name = ""
    out_ip = ""
    gateway_ip = ""
    try:
        route_tuple = conf.route.route("0.0.0.0")   # -> (iface, out_ip, gateway)
        if route_tuple and route_tuple[0]:
            iface_name = str(route_tuple[0])
            out_ip = route_tuple[1] or ""
            gateway_ip = route_tuple[2] or ""
    except Exception as exc:
        logger.warning("Default route lookup failed: %s", exc)

    # Fetch the scapy interface object matching the route's interface.
    iface = None
    if iface_name:
        try:
            from scapy.interfaces import get_working_ifaces
            for candidate in get_working_ifaces():
                if str(candidate) == iface_name:
                    iface = candidate
                    break
        except Exception:
            pass
    if iface is None:
        iface = conf.iface
        iface_name = str(iface)

    friendly = iface_display_name(iface)

    ip = getattr(iface, "ip", None) or out_ip or get_if_addr(iface_name)
    mac = getattr(iface, "mac", None) or get_if_hwaddr(iface_name)
    if not ip or not mac:
        raise RuntimeError(
            "NetGuard could not read the local IP/MAC "
            "(is Npcap installed and an interface up?)"
        )

    # netmask: prefer the interface object, else derive it from the route table
    # (scapy stores it as a packed network int there), else default to /24.
    netmask = None
    try:
        candidate = getattr(iface, "netmask", None)
        if candidate and not isinstance(candidate, int):
            netmask = str(candidate)
    except Exception:
        netmask = None
    if not netmask:
        try:
            for row in conf.route.routes:
                # row layout: (dest, mask, gateway, iface, local_ip, ...)
                if (
                    str(row[3]) == iface_name
                    and row[4] == ip
                    and row[2] == "0.0.0.0"
                    and row[1] > 0
                ):
                    netmask = str(ipaddress.ip_address(int(row[1])))
                    break
        except Exception:
            netmask = None
    if not netmask:
        netmask = "255.255.255.0"

    gateway_mac = None
    if gateway_ip:
        try:
            gateway_mac = arp_query_single(gateway_ip, iface, timeout=2)
        except Exception as exc:
            logger.warning("Gateway MAC probe failed: %s", exc)

    cidr = str(ipaddress.ip_network(f"{ip}/{netmask}", strict=False))

    info = {
        "ip": ip,
        "mac": mac,
        "netmask": str(netmask),
        "cidr": cidr,
        "gateway_ip": gateway_ip,
        "gateway_mac": gateway_mac,
        # iface_obj is the raw scapy NetworkInterface object — never serialized;
        # main.py pops it into AppState before /api/self returns a NetworkInfo.
        "iface_obj": iface,
        "iface": iface_name,
        "iface_friendly": friendly,
        "privileged": False,  # filled in by main.py (actual privilege check lives there)
    }
    logger.info(
        "Detected: iface=%s ip=%s mac=%s cidr=%s gateway=%s",
        friendly, ip, mac, cidr, gateway_ip or "unknown",
    )
    return info


# --------------------------------------------------------------------------- #
# Passive presence detection
# --------------------------------------------------------------------------- #

def _dhcp_summary(pkt) -> Optional[Tuple[str, str, str]]:
    """
    (mac, ip, hostname) of a DHCP client frame, or None. IP comes from
    requested_addr / ciaddr (empty on fresh DISCOVER frames); hostname is
    option 12 when the client sent one.
    """
    if not (pkt.haslayer(BOOTP) and pkt.haslayer(DHCP) and pkt.haslayer(Ether)):
        return None
    mac = str(pkt[Ether].src)
    if not mac or mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return None
    bootp, dhcp = pkt[BOOTP], pkt[DHCP]
    mt = None
    ip = ""
    hostname = ""
    try:
        for opt in dhcp.options:
            if isinstance(opt, tuple) and opt:
                if opt[0] == "message-type" and len(opt) > 1:
                    mt = opt[1]
                elif opt[0] == "requested_addr" and len(opt) > 1:
                    ip = str(opt[1]) or ip
                elif opt[0] == "hostname" and len(opt) > 1:
                    raw = opt[1]
                    hostname = (
                        raw.decode("utf-8", "replace") if isinstance(raw, bytes)
                        else str(raw)
                    ).strip()[:63]
            elif opt == "end":
                break
    except Exception:
        pass
    if mt not in (1, 3, 7):    # DISCOVER, REQUEST, RELEASE - client frames only
        return None
    ip = ip or str(bootp.ciaddr or "")
    try:
        if ip and (ipaddress.ip_address(ip).is_multicast or ip == "0.0.0.0"):
            ip = ""
    except ValueError:
        ip = ""
    if not ip and mt != 1:     # nothing actionable without an address
        return None
    return mac, ip, hostname


def start_passive_sniffer(
    iface,
    stop_event: threading.Event,
    on_seen: Callable[[str, str], None],
    our_mac: Optional[str] = None,
    subnets: Optional[Iterable["ipaddress.IPv4Network"]] = None,
    on_dhcp: Optional[Callable[[str, str, str], None]] = None,
    on_flow: Optional[Callable[[str, str, int], None]] = None,
    on_identify: Optional[Callable[[str, str, dict], None]] = None,
) -> threading.Thread:
    """
    Passive ARP/IP listener that keeps device presence data fresh between
    active status pings. `on_seen(mac, ip)` fires (with a dedup throttle in
    the caller) for every frame whose sender is not us/broadcast/multicast.

    Only frames that plausibly originate from a LOCAL device are accepted:
    on Wi-Fi every IP frame from the internet arrives with the gateway's
    source MAC and a foreign IP.src — counting those would pollute the
    device list, so IP-layer events are filtered against `subnets`, and
    frames that are neither ARP nor locally addressed are ignored.

    `on_dhcp(mac, ip, hostname)` fires instantly for DHCP DISCOVER/REQUEST
    frames - this is how a JUST-JOINED device shows up in real time (its
    join announcements are broadcast, so they are always visible even
    without a monitor-mode capture).

    `on_flow(src_ip, dst_ip, nbytes)` fires for every routed IP packet the
    interface receives. In checkpoint (usage-metering) mode a watched
    device's traffic passes through this host, so both directions of its
    session arrive here; membership filtering and exclusions live in the
    callback. ARP/DHCP chatter never reaches it.
    """
    our_mac_l = (our_mac or "").lower()

    def _is_local(ip: str) -> bool:
        if subnets is None:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in subnets)

    def _prn(pkt) -> None:
        try:
            # Checkpoint metering first: raw IP flow bytes for watched rooms.
            # Fires before the other early-return branches so IPv6 packets
            # (which return above) still count traffic.
            if on_flow is not None:
                if pkt.haslayer(IP) and pkt.haslayer(Ether):
                    on_flow(str(pkt[IP].src), str(pkt[IP].dst), len(pkt))
                elif pkt.haslayer(IPv6):
                    on_flow(str(pkt[IPv6].src), str(pkt[IPv6].dst), len(pkt))

            # IPv6 frames feed the NDP learning table (LL + global addresses).
            if pkt.haslayer(IPv6) and pkt.haslayer(Ether):
                mac_l = str(pkt[Ether].src).lower()
                v6 = str(pkt[IPv6].src)
                if (
                    mac_l
                    and v6
                    and not v6.startswith("ff")
                    and mac_l != our_mac_l
                    and mac_l not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
                    and not mac_l.startswith(("33:33", "01:00:5e"))
                ):
                    _remember_ipv6(mac_l, v6, v6.lower().startswith("fe80"))
                return
            # Device self-identification (mDNS "Living Room TV", SSDP smart
            # TVs) - feeds automatic icons and names, see identify.py.
            if on_identify is not None and pkt.haslayer(UDP) and pkt.haslayer(Ether):
                dport = int(pkt[UDP].dport)
                sport = int(pkt[UDP].sport)
                if dport == 5353 or sport == 5353:
                    info = identify.parse_mdns(pkt)
                    if info is not None:
                        on_identify(info["mac"], info["ip"], info)
                        return
                elif dport == 1900 or sport == 1900:
                    info = identify.parse_ssdp(pkt)
                    if info is not None:
                        on_identify(info["mac"], info["ip"], info)
                        return

            # DHCP join announcements: real-time device discovery
            if on_dhcp is not None and pkt.haslayer(UDP) and pkt.haslayer(DHCP):
                if pkt[UDP].dport == 67 or pkt[UDP].sport == 68:
                    summary = _dhcp_summary(pkt)
                    if summary is not None:
                        on_dhcp(*summary)
                    return

            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                ip, mac = arp.psrc, arp.hwsrc
                if ip == "0.0.0.0":            # unconfigured / stale ARP probe
                    return
            elif pkt.haslayer(IP) and pkt.haslayer(Ether):
                ip, mac = pkt[IP].src, pkt[Ether].src
            else:
                return
            if not ip or not mac:
                return
            if not _is_local(ip):
                return
            mac_l = mac.lower()
            if mac_l == our_mac_l or mac_l in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                return
            if mac_l.startswith(("33:33", "01:00:5e")):     # IPv6 / IPv4 multicast
                return
            try:
                if ipaddress.ip_address(ip).is_multicast:
                    return
            except ValueError:
                return
            on_seen(mac, ip)
        except Exception:
            pass  # a malformed packet must never kill the sniffer thread

    def _runner_wrapped() -> None:
        try:
            sniff(
                iface=iface,
                filter="arp or ip or ip6 or (udp and (port 67 or port 5353 or port 1900))",
                prn=_prn,
                stop_filter=lambda p: stop_event.is_set(),
                store=False,
            )
        except Exception as exc:
            logger.error("Passive sniffer stopped: %s", exc)

    thread = threading.Thread(target=_runner_wrapped, name="netguard-sniffer", daemon=True)
    thread.start()
    logger.info("Passive sniffer started on %s", iface)
    return thread
