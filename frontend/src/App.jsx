import { useEffect, useState } from "react";
import React from "react";
import {
  AlertTriangle,
  Loader2,
  MonitorSmartphone,
  Moon,
  RefreshCw,
  RotateCcw,
  Settings,
  Shield,
  ShieldCheck,
  ShieldX,
  Sun,
  Wind,
  X,
} from "lucide-react";
import DeviceTable, { Toggle } from "./DeviceTable";
import NShieldMark from "./NShieldMark";
import SettingsModal from "./SettingsModal";
import { useDevices } from "./useDevices";

/*
 * App - friendly header (protection switch), alerts, consent screen and the
 * live device list. No developer terminology: people see machines going
 * online and offline, never how it happens.
 */

/** Safety net: if the page itself ever hits a bug, show a visible panel
 * with a retry button instead of a silent black screen. */
class SafetyPanel extends React.Component {
  constructor(props) {
    super(props);
    this.state = { problem: null };
  }
  static getDerivedStateFromError(problem) {
    return { problem };
  }
  render() {
    if (this.state.problem) {
      return (
        <div className="flex min-h-screen items-center justify-center p-6">
          <div className="max-w-sm rounded-3xl border border-white/10 bg-zinc-900 p-7 text-center shadow-2xl">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-amber-500/30 bg-amber-500/10">
              <AlertTriangle className="text-amber-300" size={22} />
            </div>
            <h2 className="mt-4 text-lg font-semibold">The page hit a problem</h2>
            <p className="mt-2 text-sm text-zinc-400">
              Refreshing usually fixes it. The app itself keeps running in the background.
            </p>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="mt-5 w-full rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 py-3 font-medium text-black transition-all hover:brightness-110"
            >
              Refresh the page
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function ConsentModal({ onAccept }) {
  const [checked, setChecked] = useState(false);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur">
      <div className="w-full max-w-md rounded-3xl border border-white/10 bg-zinc-900 p-7 shadow-2xl">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-amber-500/30 bg-amber-500/10">
            <AlertTriangle className="text-amber-300" size={20} />
          </div>
          <h2 className="text-lg font-semibold">Before you start</h2>
        </div>
        <ul className="mt-5 space-y-3 text-sm leading-relaxed text-zinc-400">
          <li>Use this app <span className="text-zinc-200">only</span> on your own Wi-Fi, or on a network you are allowed to manage.</li>
          <li>Using it on a network you do not own or have permission to manage may be <span className="text-zinc-200">illegal</span> in your country.</li>
          <li>Everyone you disconnect comes back online automatically when the app closes.</li>
          <li>What happens inside the app is saved in a file on this computer.</li>
        </ul>
        <label className="mt-6 flex cursor-pointer select-none items-start gap-2.5 text-sm text-zinc-300">
          <input
            type="checkbox"
            checked={checked}
            onChange={(e) => setChecked(e.target.checked)}
            className="mt-0.5 h-4 w-4 accent-emerald-500"
          />
          This is my network, or I am allowed to manage it.
        </label>
        <button
          type="button"
          disabled={!checked}
          onClick={onAccept}
          className="mt-6 w-full rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 py-3 font-medium text-black transition-all hover:brightness-110 disabled:cursor-not-allowed disabled:bg-zinc-800 disabled:text-zinc-600"
        >
          Open NShield
        </button>
      </div>
    </div>
  );
}

function PassDoor({ onSubmit }) {
  const [code, setCode] = useState("");
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-zinc-950 p-6">
      <div className="w-full max-w-sm rounded-3xl border border-white/10 bg-zinc-900 p-7 text-center shadow-2xl">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-500/30 bg-cyan-500/10">
          <MonitorSmartphone className="text-cyan-300" size={22} />
        </div>
        <h2 className="mt-4 text-lg font-semibold">Enter the passcode</h2>
        <p className="mt-2 text-sm text-zinc-400">
          This app is protected. Ask the passcode on the computer it lives on,
          then type it here — it stays saved on this device.
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            onSubmit(code);
          }}
        >
          <input
            value={code}
            onChange={(e) => setCode(e.target.value)}
            autoFocus
            inputMode="text"
            placeholder="passcode"
            className="mt-5 w-full rounded-xl border border-zinc-700 bg-zinc-950 px-4 py-3 text-center font-mono text-lg tracking-widest text-zinc-100 outline-none focus:border-cyan-500/60"
          />
          <button
            type="submit"
            disabled={code.trim().length < 4}
            className="mt-4 w-full rounded-xl bg-gradient-to-r from-cyan-500 to-sky-500 py-3 font-medium text-black transition-all hover:brightness-110 disabled:cursor-not-allowed disabled:bg-zinc-800 disabled:text-zinc-600"
          >
            Open
          </button>
        </form>
      </div>
    </div>
  );
}

function JoinAlert({ alert, onDismiss }) {
  const device = alert.device || {};
  const who = device.custom_name || device.auto_name || device.hostname || device.vendor || `a device (${device.ip})`;
  return (
    <div className="flex items-center gap-3 rounded-2xl border border-cyan-500/30 bg-cyan-500/10 px-5 py-3.5 text-sm text-cyan-100 shadow-lg shadow-cyan-950/20">
      <Wind size={18} className="shrink-0 text-cyan-300" />
      <p className="flex-1">
        <span className="font-semibold">New device on your Wi-Fi:</span>{" "}
        <span className="font-medium">{who}</span>
      </p>
      <button
        type="button"
        onClick={() => onDismiss(alert.id)}
        className="p-0.5 text-cyan-300/60 transition-colors hover:text-cyan-300"
        aria-label="Dismiss"
      >
        <X size={16} />
      </button>
    </div>
  );
}

function AdminBanner() {
  return (
    <div className="flex items-start gap-3 rounded-2xl border border-amber-500/20 bg-amber-500/10 px-5 py-4 text-sm text-amber-200 shadow-lg shadow-amber-950/10">
      <AlertTriangle size={18} className="mt-0.5 shrink-0" />
      <p>
        <span className="font-semibold">Admin permission is needed.</span>{" "}
        Close the app and start it again from <span className="rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-xs">run.bat</span>{" "}
        — answer <span className="font-medium">"Yes"</span> when your computer asks for permission.
      </p>
    </div>
  );
}

function NetworkBanner({ net, allowedSubnets }) {
  const allowed = allowedSubnets?.length ? allowedSubnets.join(", ") : "(none yet)";
  return (
    <div className="flex items-start gap-3 rounded-2xl border border-rose-500/30 bg-rose-500/10 px-5 py-4 text-sm text-rose-200 shadow-lg shadow-rose-950/20">
      <ShieldX size={18} className="mt-0.5 shrink-0 text-rose-300" />
      <p>
        <span className="font-semibold">This is not the network this app was set up for.</span>{" "}
        You are currently on <span className="rounded bg-rose-500/15 px-1.5 py-0.5">{net?.cidr || "an unknown network"}</span>{" "}
        but the app only works on <span className="rounded bg-rose-500/15 px-1.5 py-0.5">{allowed}</span>.
        Disconnecting devices is off. Restart the app while connected to the right network.
      </p>
    </div>
  );
}

export default function App() {
  const {
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
    counts,
    sparks,
  } = useDevices();

  const [consented, setConsented] = useState(() => {
    try {
      return window.localStorage.getItem("nshield-consent") === "1";
    } catch {
      return false;
    }
  });
  const acceptConsent = () => {
    try {
      window.localStorage.setItem("nshield-consent", "1");
    } catch {
      /* private mode etc. - still proceed */
    }
    setConsented(true);
  };

  const [settingsOpen, setSettingsOpen] = useState(false);

  // Daytime look: a simple re-pointing of the same palette (see index.css).
  const [light, setLight] = useState(() => {
    try {
      return window.localStorage.getItem("nshield-theme") === "light";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    const root = document.documentElement;
    if (light) root.setAttribute("data-theme", "light");
    else root.removeAttribute("data-theme");
    try {
      window.localStorage.setItem("nshield-theme", light ? "light" : "dark");
    } catch { /* private mode */ }
  }, [light]);

  const adminOk = net?.privileged ?? false;

  if (gate === "locked") {
    return (
      <SafetyPanel>
        <PassDoor onSubmit={submitPass} />
      </SafetyPanel>
    );
  }
  if (gate === "checking") {
    return (
      <SafetyPanel>
        <div className="flex min-h-screen items-center justify-center">
          <div className="flex flex-col items-center gap-4 text-zinc-500">
            <NShieldMark size={46} accent="#E5E7EB" />
            <Loader2 className="animate-spin" size={20} />
          </div>
        </div>
      </SafetyPanel>
    );
  }

  return (
    <SafetyPanel>
      <div className="min-h-screen">
      {!consented && <ConsentModal onAccept={acceptConsent} />}

      {/* ------------------------------------------------ header -------- */}
      <header className="sticky top-0 z-40 border-b border-white/5 bg-zinc-950/70 backdrop-blur-xl">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-4 py-4">
          <div className="flex items-center gap-3">
            <div
              className={`flex h-11 w-11 items-center justify-center rounded-2xl border transition-colors ${
                master
                  ? "border-emerald-500/40 bg-gradient-to-br from-emerald-500/20 to-teal-500/10"
                  : "border-zinc-800 bg-zinc-900 text-zinc-200"
              }`}
            >
              <NShieldMark size={24} accent={master ? "#22D3EE" : "#E5E7EB"} />
            </div>
            <div>
              <h1 className="text-lg font-bold leading-none tracking-tight">NShield</h1>
              <p className="mt-1.5 text-xs text-zinc-500">Keep strangers off your Wi-Fi</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setLight((v) => !v)}
              title={light ? "Evening look" : "Daytime look"}
              aria-label={light ? "Switch to the dark look" : "Switch to the light look"}
              className="flex h-10 w-10 items-center justify-center rounded-xl border border-zinc-800 bg-zinc-900/70 text-zinc-400 transition-colors hover:border-zinc-700 hover:text-zinc-200"
            >
              {light ? <Sun size={18} className="text-amber-500" /> : <Moon size={18} />}
            </button>
            <button
              type="button"
              onClick={() => setSettingsOpen(true)}
              title="Options"
              aria-label="Options"
              className="flex h-10 w-10 items-center justify-center rounded-xl border border-zinc-800 bg-zinc-900/70 text-zinc-400 transition-colors hover:border-zinc-700 hover:text-zinc-200"
            >
              <Settings size={18} />
            </button>
          </div>

          {/* protection switch */}
          <div
            className={`flex items-center gap-4 rounded-2xl border px-5 py-3 shadow-lg transition-all ${
              master
                ? "border-emerald-500/30 bg-emerald-500/10 shadow-emerald-950/20"
                : "border-zinc-800 bg-zinc-900/60 shadow-black/20"
            }`}
          >
            <div>
              <div className="flex items-center gap-2 text-sm font-semibold">
                {master ? (
                  <ShieldCheck size={16} className="text-emerald-400" />
                ) : (
                  <Shield size={16} className="text-zinc-500" />
                )}
                {master ? "Protection on" : "Protection off"}
                <span
                  className={`ml-1 h-2 w-2 rounded-full ${
                    connected
                      ? "animate-pulse bg-emerald-400"
                      : "bg-zinc-700"
                  }`}
                  title={connected ? "Connected live" : "Connecting..."}
                />
              </div>
              <div className="mt-0.5 text-xs text-zinc-500">
                {adminOk
                  ? counts.blocked === 0
                    ? "Everyone is back online"
                    : `${counts.blocked} cut off`
                  : "Start it the right way first"}
              </div>
            </div>
            <Toggle
              size="lg"
              checked={master}
              disabled={!adminOk}
              disabledTitle="Start the app with admin permission first"
              onChange={() => toggleMaster(!master)}
            />
          </div>
        </div>

        {compliant === false && <NetworkBanner net={net} allowedSubnets={allowedSubnets} />}
      </header>

      {/* ------------------------------------------------ main ---------- */}
      <main className="mx-auto max-w-6xl space-y-6 px-4 py-8">
        {joinAlerts.slice(-3).map((alert) => (
          <JoinAlert key={alert.id} alert={alert} onDismiss={dismissJoinAlert} />
        ))}

        {net && !adminOk && <AdminBanner />}

        {error && (
          <div className="flex items-start gap-3 rounded-2xl border border-rose-500/30 bg-rose-500/10 px-5 py-4 text-sm text-rose-200">
            <AlertTriangle size={18} className="mt-0.5 shrink-0" />
            <p className="flex-1">{error}</p>
            <button
              type="button"
              onClick={clearError}
              className="p-0.5 text-rose-300/70 transition-colors hover:text-rose-300"
              aria-label="Dismiss"
            >
              <X size={16} />
            </button>
          </div>
        )}

        <section className="card">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/5 px-6 py-5">
            <div>
              <h2 className="text-base font-semibold text-zinc-50">Devices</h2>
              <p className="mt-1 flex items-center gap-1.5 text-xs text-zinc-500">
                <span className={`h-1.5 w-1.5 rounded-full ${counts.total ? "bg-emerald-400" : "bg-zinc-700"}`} />
                {counts.total} found · {counts.online} connected · {counts.blocked} cut off
                {counts.watched > 0 && (
                  <> · {counts.watched} watched — cutting off is paused while watching</>
                )}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={restoreAll}
                disabled={counts.blocked === 0 || !adminOk}
                title={
                  !adminOk
                    ? "Start the app with admin permission first"
                    : "Everyone comes back online - protection stays on"
                }
                className="flex items-center gap-2 rounded-xl border border-zinc-700/80 bg-zinc-800/50 px-4 py-2.5 text-sm font-medium text-zinc-200 transition-all hover:border-zinc-600 hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-40"
              >
                <RotateCcw size={15} />
                Restore everyone
              </button>
              <button
                type="button"
                onClick={rescan}
                disabled={scanning || !net}
                className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 px-4 py-2.5 text-sm font-semibold text-black shadow-lg shadow-emerald-950/30 transition-all hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {scanning ? (
                  <Loader2 size={15} className="animate-spin" />
                ) : (
                  <RefreshCw size={15} />
                )}
                {scanning ? "Looking..." : "Find devices"}
              </button>
            </div>
          </div>

          <DeviceTable
            devices={devices}
            gatewayIp={net?.gateway_ip || ""}
            selfIp={net?.ip || ""}
            master={master}
            privileged={adminOk}
            anyBlocked={counts.blocked > 0}
            onToggle={(device) => setBlocked(device.ip, !device.blocked)}
            onWatch={(device) => setWatched(device.ip, !device.watched)}
            onCap={(ip, downKbps, upKbps, quotaMb) => setCaps(ip, downKbps, upKbps, quotaMb)}
            onRename={(mac, name, icon) => rename(mac, name, icon)}
            sparks={sparks}
          />
        </section>

        <SettingsModal
          open={settingsOpen}
          onClose={() => setSettingsOpen(false)}
          onChanged={() => {}}
          onExport={exportCsv}
        />

        <footer className="pb-10 pt-2 text-center text-xs leading-relaxed text-zinc-600">
          This tool works only on the network you approved, and only on a network that belongs to you.
          <br />
          If the app closes, everything it disconnected comes back online by itself, and everyone it
          was counting goes straight back to normal.
        </footer>
      </main>
      </div>
    </SafetyPanel>
  );
}
