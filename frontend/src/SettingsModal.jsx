import { useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  Bell,
  BellOff,
  Laptop,
  Loader2,
  MonitorSmartphone,
  RefreshCw,
  ShieldCheck,
  X,
} from "lucide-react";
import { getSavedPass, post } from "./useDevices";

/**
 * SettingsModal - three house switches in one quiet place:
 *   * phone access (passcode + QR code so phones can reach the page)
 *   * join alerts (page banner + Windows notification)
 *   * start with Windows (hidden at boot, always on duty)
 */

const TOGGLE_BTN =
  "relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition-all duration-200";

function ToggleRow({ icon: Icon, title, subtitle, checked, busy, disabledTitle, onChange }) {
  return (
    <div className="flex items-center justify-between gap-4 py-3.5">
      <div className="flex min-w-0 items-start gap-3">
        <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-zinc-700/70 bg-zinc-800/50 text-zinc-300">
          <Icon size={17} />
        </div>
        <div className="min-w-0">
          <p className="text-sm font-medium text-zinc-100">{title}</p>
          <p className="mt-0.5 text-xs leading-relaxed text-zinc-500">{subtitle}</p>
        </div>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={busy}
        onClick={() => onChange(!checked)}
        className={`${TOGGLE_BTN} ${
          checked
            ? "border-transparent bg-gradient-to-r from-emerald-500 to-teal-500"
            : "border-zinc-700 bg-zinc-700/60"
        } ${busy ? "cursor-wait opacity-60" : "cursor-pointer hover:brightness-110"}`}
      >
        <span
          className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transition-transform ${
            checked ? "translate-x-[22px]" : "translate-x-[2px]"
          }`}
        />
      </button>
    </div>
  );
}

export default function SettingsModal({ open, onClose, onChanged, onExport }) {
  const [data, setData] = useState(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const [passDraft, setPassDraft] = useState("");
  const [problem, setProblem] = useState("");

  useEffect(() => {
    if (!open) return;
    let alive = true;
    setData(null);
    setNote("");
    setProblem("");
    setPassDraft("");
    const headers = {};
    const p = getSavedPass();
    if (p) headers["x-nshield-pass"] = p;
    fetch("/api/settings", { headers })
      .then((r) => r.json())
      .then((payload) => {
        if (alive) setData(payload);
      })
      .catch(() => {
        if (alive) setProblem("Could not load the settings.");
      });
    return () => {
      alive = false;
    };
  }, [open]);

  const apply = async (payload, successNote) => {
    setBusy(true);
    setProblem("");
    try {
      await post("/api/settings", payload);
      setNote(successNote);
      // refetch
      const headers = {};
      const p = getSavedPass();
      if (p) headers["x-nshield-pass"] = p;
      const res = await fetch("/api/settings", { headers });
      setData(await res.json());
      onChanged?.();
    } catch (e) {
      setProblem(e.message);
    } finally {
      setBusy(false);
    }
  };

  if (!open) return null;

  const phoneOn = !!data?.phone_access;
  const qrUrl = data?.lan_url ? `${data.lan_url}?pass=${data.passcode}` : "";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur">
      <div className="w-full max-w-md rounded-3xl border border-white/10 bg-zinc-900 p-6 shadow-2xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-500/10">
              <ShieldCheck size={17} className="text-cyan-300" />
            </div>
            <h3 className="font-semibold leading-none">Options</h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-300"
            aria-label="Close"
          >
            <X size={16} />
          </button>
        </div>

        {!data ? (
          <div className="flex items-center justify-center py-10 text-zinc-500">
            <Loader2 className="animate-spin" size={22} />
          </div>
        ) : (
          <>
            {/* phone access -------------------------------------------------- */}
            <div className="mt-3">
              <ToggleRow
                icon={MonitorSmartphone}
                title="Use the app from your phone"
                subtitle="Computers and phones on this Wi-Fi can open the page - protected by a passcode."
                checked={phoneOn}
                busy={busy}
                onChange={(v) => apply({ phone_access: v }, v ? "Phone access is on" : "Phone access is off")}
              />
              {phoneOn && (
                <div className="rounded-2xl border border-cyan-500/20 bg-cyan-500/5 p-4">
                  <p className="text-xs text-zinc-400">
                    Point your phone camera at this to open the app:
                  </p>
                  <div className="mt-3 flex items-center gap-4">
                    <div className="rounded-xl bg-white p-2 shadow">
                      <QRCodeSVG value={qrUrl} size={96} />
                    </div>
                    <div className="min-w-0 text-xs">
                      <p className="text-zinc-500">Passcode</p>
                      <p className="mt-0.5 rounded-lg bg-zinc-800 px-2.5 py-1.5 font-mono text-base tracking-widest text-cyan-300">
                        {data.passcode}
                      </p>
                      <p className="mt-2 truncate text-zinc-600">{data.lan_url}</p>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="my-1 border-t border-white/5" />

            {/* join alerts ---------------------------------------------------- */}
            <ToggleRow
              icon={data?.alerts_on ? Bell : BellOff}
              title="New device alerts"
              subtitle="The page shows a banner (and Windows shows a note) when a device joins this Wi-Fi for the first time."
              checked={!!data?.alerts_on}
              busy={busy}
              onChange={(v) => apply({ alerts_on: v }, v ? "Join alerts on" : "Join alerts off")}
            />

            <div className="my-1 border-t border-white/5" />

            {/* autostart ------------------------------------------------------ */}
            <ToggleRow
              icon={Laptop}
              title="Start automatically"
              subtitle="Starts by itself when Windows starts, hidden, no window - always keeping watch."
              checked={!!data?.autostart}
              busy={busy}
              onChange={(v) => apply({ autostart: v }, v ? "Starts with Windows now" : "No longer starts with Windows")}
            />

            {/* report download ------------------------------------------------- */}
            {onExport && (
              <>
                <div className="my-1 border-t border-white/5" />
                <div className="flex items-center justify-between gap-4 py-3.5">
                  <div>
                    <p className="text-sm font-medium text-zinc-100">Save a report</p>
                    <p className="mt-0.5 text-xs text-zinc-500">
                      A spreadsheet of everything that was metered while the
                      app watched devices - by day, per device.
                    </p>
                  </div>
                  <div className="flex shrink-0 gap-2">
                    <button
                      type="button"
                      onClick={() => onExport(7)}
                      title="Last 7 days"
                      className="rounded-lg border border-zinc-700 bg-zinc-800/60 px-3 py-2 text-xs font-medium text-zinc-200 transition-colors hover:border-zinc-600"
                    >
                      7 days
                    </button>
                    <button
                      type="button"
                      onClick={() => onExport(30)}
                      title="Last 30 days"
                      className="rounded-lg border border-zinc-700 bg-zinc-800/60 px-3 py-2 text-xs font-medium text-zinc-200 transition-colors hover:border-zinc-600"
                    >
                      30 days
                    </button>
                  </div>
                </div>
              </>
            )}

            {/* passcode change (only when phone access exists) ----------------- */}
            {phoneOn && (
              <>
                <div className="my-1 border-t border-white/5" />
                <p className="mt-3 text-xs font-medium text-zinc-400">Change the passcode</p>
                <div className="mt-1.5 flex gap-2">
                  <input
                    value={passDraft}
                    onChange={(e) => setPassDraft(e.target.value)}
                    placeholder="4-12 characters"
                    className="w-40 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-100 outline-none focus:border-cyan-500/60"
                  />
                  <button
                    type="button"
                    disabled={busy || passDraft.trim().length < 4}
                    onClick={async () => {
                      await apply({ passcode: passDraft.trim() }, "Passcode updated");
                      setPassDraft("");
                    }}
                    className="flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-800/60 px-3 py-2 text-xs font-medium text-zinc-200 transition-all hover:border-zinc-600 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <RefreshCw size={13} />
                    Change
                  </button>
                </div>
              </>
            )}
          </>
        )}

        {problem && (
          <p className="mt-3 rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
            {problem}
          </p>
        )}
        {note && !problem && (
          <p className="mt-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300">
            {note}
          </p>
        )}
      </div>
    </div>
  );
}
