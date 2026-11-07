"""Windows QoS speed caps for watched devices.

Caps are enforced by Windows QoS policies in the ActiveStore, applied to
the packets this PC relays. Auto-removed when the watch is released.
Windows-only: on other platforms qos_set_cap/qos_clear_cap are no-ops.
"""

import subprocess

import logging
logger = logging.getLogger("netguard")

QOS_MIN_KBPS = 8          # below this the OS throttling granularity is noise
QOS_BITS_FLOOR = 8192     # 1 KB/s absolute floor for the policy value


def _ps_run(command: str):
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, timeout=20, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _qos_name(ip: str, kind: str) -> str:
    return f"netguard_cap_{kind}_{ip}"


def _qos_policy_args(kind: str, ip: str, bits: int) -> str:
    # Upload cap -> throttle packets leaving this PC with src = device IP.
    # Download cap -> throttle packets leaving this PC with dst = device IP.
    prefix = "IPSrcPrefixMatchCondition" if kind == "up" else "IPDstPrefixMatchCondition"
    name = _qos_name(ip, kind)
    return (
        f"New-NetQosPolicy -PolicyStore ActiveStore -Name '{name}' "
        f"-{prefix} '{ip}/32' -ThrottleRateActionBitsPerSecond {bits}"
    )


def qos_set_cap(state, ip: str, kind: str, kbps: int) -> bool:
    """Install/re-install one throttle policy. Returns True when active."""
    bits = max(int(kbps) * 8 * 1024, QOS_BITS_FLOOR)
    qos_clear_cap(state, ip, kind)              # rates cannot be edited in place
    result = _ps_run(_qos_policy_args(kind, ip, bits))
    tail = (result.stdout + result.stderr).decode(errors="replace").strip()[:150]
    if result.returncode != 0 or "error" in tail.lower():
        logger.warning("CAP set failed for %s %s: %s", ip, kind, tail)
        return False
    logger.info("CAP %s %s %d KB/s - QoS policy active (%s)", ip, kind, kbps, _qos_name(ip, kind))
    return True


def qos_clear_cap(state, ip: str, kind: str) -> bool:
    """Remove one throttle policy (no-op with a friendly log when absent)."""
    try:
        result = _ps_run(
            f"Remove-NetQosPolicy -PolicyStore ActiveStore "
            f"-Name '{_qos_name(ip, kind)}' -Confirm:$false"
        )
        ok = result.returncode == 0
        if ok:
            logger.info("CAP %s %s removed - no limit again", ip, kind)
        return ok
    except Exception as exc:
        logger.warning("CAP clear failed for %s %s: %s", ip, kind, exc)
        return False


__all__ = [
    "QOS_MIN_KBPS", "QOS_BITS_FLOOR", "qos_set_cap", "qos_clear_cap",
]
