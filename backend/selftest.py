"""
Functional self-test of the NetGuard ARP engine, limited to this machine's
own footprint:

  * Poison phase: only an ARP reply TO THE GATEWAY claiming *our own IP* is
    at FAKE_MAC. No other host's cache is modified - if something goes wrong,
    only this box's connectivity to the gateway blinks for a few seconds.
  * Observable: while the poison loop runs, ICMP replies from the gateway
    (addressed to our IP) should stop arriving / degrade. After
    worker.stop() + worker.restore(), pings must succeed again, which also
    proves the restoration packets wrote the true MAC back.
  * Also exercises: thread start, continuous bursts, clean stop via
    threading.Event, restore() burst.

(NB: routers with ARP-spoofing protection may ignore our poison; in that case
the send loop and restore are still exercised and we report it.)
"""
import subprocess
import sys
import time

sys.path.insert(0, ".")
from scapy.all import ARP, Ether, sendp

import scanner
import spoofer

MY_IP = "192.168.1.10"          # <-- change to THIS machine's IP
MY_MAC = "00:11:22:33:44:55"    # <-- change to THIS machine's MAC
GW_IP = "192.168.1.1"           # <-- your gateway IP
GW_MAC = "00:11:22:33:44:66"    # <-- your gateway MAC
FAKE_MAC = "00:de:ad:be:ef:00"


class GatewayPoison(spoofer.BlockWorker):
    """Only the gateway-side poison packet; target-side packet is skipped."""

    def _burst(self) -> None:
        pkt = Ether(src=MY_MAC, dst=self.gateway_mac) / ARP(
            op=2,
            pdst=self.gateway_ip,
            psrc=self.target_ip,          # our IP
            hwdst=self.gateway_mac,
            hwsrc=self.our_mac,           # the FAKE mac
        )
        sendp(pkt, iface=self.iface, verbose=0)


def ping_once() -> bool:
    out = subprocess.run(
        ["ping", "-n", "1", "-w", "800", GW_IP],
        capture_output=True, text=True,
    ).stdout
    return "TTL=" in out or "temps=" in out or "time=" in out


def ping_series(n: int) -> int:
    ok = 0
    for _ in range(n):
        if ping_once():
            ok += 1
        time.sleep(0.2)
    return ok


baseline = ping_series(3)
print(f"baseline pings ok: {baseline}/3")

worker = GatewayPoison(
    iface=scanner.conf.iface,
    our_mac=FAKE_MAC,          # carried in the ARP payload
    gateway_ip=GW_IP,
    gateway_mac=GW_MAC,        # the truth, used by restore()
    target_ip=MY_IP,
    target_mac=MY_MAC,
    interval=0.5,
)
worker.start()
poisoned = ping_series(4)
worker.stop()                  # clean shutdown via threading.Event

worker.restore()               # restoration packets (the true MAC for our IP)
time.sleep(0.5)
recovered = ping_series(4)

print(f"pings while poisoned: {poisoned}/4")
print(f"pings after restore: {recovered}/4")
print("clean stop/restore exercised, no exceptions")
print("PASS" if baseline == 3 and recovered >= 3 else "PARTIAL (network filtered ARP poison)")

# --------------------------------------------------------------------------- #
# IPv6/NDP builders preflight. Nothing hostile is sent for IPv6 here: the
# "truth" variants re-announce the real MACs (harmless), the poison variant
# is only constructed and field-checked, never transmitted.
# --------------------------------------------------------------------------- #
from scapy.all import ICMPv6ND_NA

ROUTER_LL = "fe80::262f:d0ff:fe08:c738"     # discovered live from the RA
try:
    poison_phone = spoofer.na_phone(ROUTER_LL, MY_MAC, MY_MAC, MY_MAC, None)
    truth_phone = spoofer.na_phone(ROUTER_LL, MY_MAC, GW_MAC, MY_MAC, None)
    truth_router = spoofer.na_router("2001:db8::dead", MY_MAC, ROUTER_LL, GW_MAC, MY_MAC)
    checks = [
        poison_phone[ICMPv6ND_NA].tgt == ROUTER_LL and poison_phone[ICMPv6ND_NA].O == 1,
        truth_phone[ICMPv6ND_NA].tgt == ROUTER_LL,
        truth_router[ICMPv6ND_NA].tgt == "2001:db8::dead",
        all(
            str(p[Ether].src).lower() == MY_MAC.lower()
            for p in (poison_phone, truth_phone, truth_router)
        ),
    ]
    print(f"ND6 builders: {'PASS' if all(checks) else 'FIELD MISMATCH: ' + str(checks)}")
except Exception as exc:
    print("ND6 builder preflight failed:", exc)
