import { useCallback, useEffect, useRef, useState } from "react";

/**
 * useDevices — passcode gate + REST bootstrap + WebSocket live status.
 *
 * If the page is opened from a phone (or any other device on the Wi-Fi) it
 * must show the passcode door first: the backend refuses /api/* without the
 * code over the network. The code is remembered on the device, so the door
 * only appears once per device (or after it changes).
 *
 * The live socket pushes full {type:"snapshot"} messages on every backend
 * tick and after every action, plus {type:"new_device"} join alerts.
 */

const PASS_KEY = "nshield-pass";
const JSON_HEADERS = { "Content-Type": "application/json" };

export function getSavedPass() {
  try {
    return window.localStorage.getItem(PASS_KEY) || "";
  } catch {
    return "";
  }
}

function savePass(code) {
  try {
    if (code) window.localStorage.setItem(PASS_KEY, code);
    else window.localStorage.removeItem(PASS_KEY);
  } catch {
    /* private mode */
  }
}

export async function post(url, body, pass = getSavedPass()) {
  const headers = { ...JSON_HEADERS };
  if (pass) headers["x-nshield-pass"] = pass;
  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const payload = await res.json().catch(() => ({}));
    throw new Error(payload.detail || `${res.status} ${res.statusText}`);
  }
  return res.json();
}

async function getJson(url, pass = getSavedPass()) {
  const headers = {};
  if (pass) headers["x-nshield-pass"] = pass;
  const res = await fetch(url, { headers });
  if (!res.ok) {
    const payload = await res.json().catch(() => ({}));
    throw new Error(payload.detail || `${res.status} ${res.statusText}`);
  }
  return res.json();
}

export function useDevices() {
  const [devices, setDevices] = useState([]);
  const [net, setNet] = useState(null);
  const [master, setMaster] = useState(false);
  const [compliant, setCompliant] = useState(true);
  const [allowedSubnets, setAllowedSubnets] = useState([]);
  const [connected, setConnected] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");

  // passcode door: "checking" | "open" | "locked"
  const [gate, setGate] = useState("checking");
  const [pass, setPass] = useState(getSavedPass);
  const lockedRef = useRef(false);   // gate_required -> stop reconnect attempts

  // "a new device joined" banners
  const [joinAlerts, setJoinAlerts] = useState([]);

  // Rolling speed history for the tiny graphs, keyed by IP: only watched
  // devices are sampled (their rates are live); one point per snapshot,
  // capped so the last minute or so is kept.
  const SPARK_MAX = 60;
  const sparksRef = useRef({});
  const [sparks, setSparks] = useState({});

  const recordSpark = useCallback((deviceList) => {
    const now = {};
    for (const d of deviceList) {
      if (!d.watched) continue;
      const key = d.ip;
      const prev = sparksRef.current[key] || [];
      const last = prev[prev.length - 1];
      const next = {
        down: d.down_rate || 0,
        up: d.up_rate || 0,
      };
      // Skip duplicate ticks (action bursts send several snapshots at once).
      if (last && Math.abs(last.down - next.down) < 1 && Math.abs(last.up - next.up) < 1) {
        now[key] = prev;
        continue;
      }
      const list = [...prev, next];
      if (list.length > SPARK_MAX) list.splice(0, list.length - SPARK_MAX);
      now[key] = list;
    }
    sparksRef.current = now;
    setSparks(now);
  }, []);

  const wsRef = useRef(null);
  const retriesRef = useRef(0);
  const passRef = useRef(pass);
  passRef.current = pass;

  // (re)bootstrap whenever the pass changes and the door is open
  useEffect(() => {
    if (gate !== "open") return;
    let alive = true;
    let reconnectTimer;
    const auth = () =>
      passRef.current ? { "x-nshield-pass": passRef.current } : {};

    fetch("/api/self", { headers: auth() })
      .then((r) => {
        if (r.status === 401) throw new Error("Gate: saved passcode no longer valid");
        return r.json();
      })
      .then((d) => {
        if (!alive) return;
        if (d.net) setNet(d.net);
        setMaster(!!d.master);
        setCompliant(d.compliant !== false);
        setAllowedSubnets(d.allowed_subnets || []);
      })
      .catch((e) => {
        if (String(e.message).startsWith("Gate:")) {
          lockedRef.current = true;
          savePass("");
          setPass("");
          setGate("locked");
        }
        return null;
      });

    fetch("/api/devices", { headers: auth() })
      .then((r) => {
        if (r.status === 401) throw new Error("Gate: 2");
        return r.json();
      })
      .then((d) => {
        if (!alive) return;
        setDevices(d.devices || []);
        setMaster(!!d.master);
      })
      .catch(() => null);

    const connect = () => {
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      const authQs = passRef.current
        ? `?pass=${encodeURIComponent(passRef.current)}`
        : "";
      const ws = new WebSocket(`${proto}://${window.location.host}/api/ws${authQs}`);
      wsRef.current = ws;

      ws.onopen = () => {
        retriesRef.current = 0;
        if (alive) setConnected(true);
      };
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === "gate_required") {
            lockedRef.current = true;
            savePass("");
            setPass("");
            setGate("locked");
            try { ws.close(); } catch { /* noop */ }
            return;
          }
          if (data.type === "snapshot") {
            setDevices(data.devices || []);
            setMaster(!!data.master);
            if (data.net) setNet(data.net);
            if (data.compliant !== undefined) setCompliant(!!data.compliant);
            if (data.allowed_subnets) setAllowedSubnets(data.allowed_subnets);
            recordSpark(data.devices || []);
          } else if (data.type === "new_device") {
            setJoinAlerts((list) => [
              ...list,
              { id: `${Date.now()}-${Math.random()}`, device: data.device },
            ]);
          } else if (data.type === "notice") {
            setError(data.text || "Notice from the guard.");
          }
        } catch {
          /* ignore malformed frames */
        }
      };
      ws.onclose = () => {
        if (!alive || lockedRef.current) return;
        setConnected(false);
        const delay = Math.min(1000 * 2 ** retriesRef.current++, 10000);
        reconnectTimer = setTimeout(connect, delay);
      };
      ws.onerror = () => ws.close();
    };

    connect();

    return () => {
      alive = false;
      clearTimeout(reconnectTimer);
      try {
        wsRef.current?.close();
      } catch {
        /* noop */
      }
    };
  }, [gate, pass, recordSpark]);

  // first load: ask the backend whether this device needs the passcode
  useEffect(() => {
    let alive = true;
    fetch("/api/gate")
      .then((r) => r.json())
      .then((d) => {
        if (!alive) return;
        if (d.needed && !passRef.current) setGate("locked");
        else setGate("open");
      })
      .catch(() => {
        if (alive) setGate("locked");   // backend unreachable: safest door
      });
    return () => {
      alive = false;
    };
  }, []);

  const submitPass = useCallback((code) => {
    const cleaned = String(code || "").trim();
    savePass(cleaned);
    lockedRef.current = false;
    setPass(cleaned);
    setConnected(false);
    setGate("open");          // the bootstrap effect re-runs with the new code
  }, []);

  const rescan = useCallback(async () => {
    setError("");
    setScanning(true);
    try {
      await post("/api/scan", {});
    } catch (e) {
      setError(e.message);
    } finally {
      setScanning(false);
    }
  }, []);

  const setBlocked = useCallback(async (ip, blocked) => {
    setError("");
    try {
      await post(blocked ? "/api/block" : "/api/unblock", { ip });
    } catch (e) {
      setError(e.message);
    }
  }, []);

  const toggleMaster = useCallback(async (enabled) => {
    setError("");
    try {
      await post("/api/master", { enabled });
    } catch (e) {
      setError(e.message);
    }
  }, []);

  // Unblock every device (send restoration ARPs) without touching the master
  // switch - the backend keeps protection enabled. Also releases any usage
  // watches (forwarding off).
  const restoreAll = useCallback(async () => {
    setError("");
    try {
      await post("/api/restore-all", {});
    } catch (e) {
      setError(e.message);
    }
  }, []);

  // Checkpoint mode: start/stop watching one device's data usage (its
  // traffic is counted while it passes through this PC). Impossible while
  // another device is cut off - the app refuses with a friendly message.
  const setWatched = useCallback(async (ip, enabled) => {
    setError("");
    try {
      await post("/api/watch", { ip, enabled });
    } catch (e) {
      setError(e.message);
    }
  }, []);

  // Speed limits for a watched device (KB/s; empty/null = no limit), plus an
  // optional daily data budget in MB that auto-disconnects when reached.
  const setCaps = useCallback(async (ip, downKbps, upKbps, quotaMb) => {
    setError("");
    try {
      await post("/api/cap", {
        ip,
        down_kbps: downKbps > 0 ? downKbps : null,
        up_kbps: upKbps > 0 ? upKbps : null,
        quota_mb: quotaMb != null && quotaMb >= 0 ? Math.round(quotaMb) : null,
      });
    } catch (e) {
      setError(e.message);
    }
  }, []);

  // Save a spreadsheet of everything that was metered lately.
  const exportCsv = useCallback(async (days = 30) => {
    setError("");
    try {
      const p = getSavedPass();
      const res = await fetch(`/api/export?days=${days}`, {
        headers: p ? { "x-nshield-pass": p } : {},
      });
      if (!res.ok) throw new Error("Could not make the report.");
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "nshield-usage.csv";
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    } catch (e) {
      setError(e.message);
    }
  }, []);

  // Friendly names: remembered forever on this computer, by device id.
  const rename = useCallback(async (mac, name, icon) => {
    setError("");
    try {
      await post("/api/rename", { mac, name: name || "", icon: icon || "" });
    } catch (e) {
      setError(e.message);
    }
  }, []);

  const dismissJoinAlert = useCallback((id) => {
    setJoinAlerts((list) => list.filter((a) => a.id !== id));
  }, []);

  const clearError = useCallback(() => setError(""), []);

  const blockedCount = devices.filter((d) => d.blocked).length;
  const onlineCount = devices.filter((d) => d.online && !d.blocked).length;
  const watchedCount = devices.filter((d) => d.watched).length;

  return {
    devices,
    net,
    master,
    compliant,
    allowedSubnets,
    connected,
    scanning,
    error,
    gate,
    submitPass,
    joinAlerts,
    dismissJoinAlert,
    rename,
    rescan,
    setBlocked,
    setWatched,
    setCaps,
    exportCsv,
    toggleMaster,
    restoreAll,
    clearError,
    sparks,
    counts: {
      total: devices.length,
      blocked: blockedCount,
      online: onlineCount,
      watched: watchedCount,
    },
  };
}
