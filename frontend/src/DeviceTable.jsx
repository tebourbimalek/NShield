import { useState } from "react";
import DeviceIcon, { ICON_LIST } from "./DeviceIcon";
import Sparkline from "./Sparkline";
import { Eye, EyeOff, Gauge, Pencil, PieChart, ShieldX, Wifi, WifiOff, X } from "lucide-react";

/**
 * DeviceTable - live list with per-row disconnect switches and (checkpoint
 * mode) per-device data-usage watching. Also exports the reusable <Toggle>.
 */

export function Toggle({ checked, onChange, disabled = false, size = "sm", disabledTitle = "Turn on protection first" }) {
  const dims =
    size === "lg"
      ? { track: "h-7 w-12", knob: "h-6 w-6", off: "translate-x-[2px] translate-y-[2px]", on: "translate-x-[22px] translate-y-[2px]" }
      : { track: "h-6 w-11", knob: "h-5 w-5", off: "translate-x-[2px] translate-y-[2px]", on: "translate-x-[22px] translate-y-[2px]" };

  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={onChange}
      title={disabled ? disabledTitle : checked ? "Put back online" : "Disconnect"}
      className={`relative inline-flex shrink-0 items-center rounded-full border transition-all duration-200 ${
        dims.track
      } ${checked ? "border-transparent bg-gradient-to-r from-rose-500 to-red-500" : "border-zinc-700 bg-zinc-700/60"} ${
        disabled ? "cursor-not-allowed opacity-40" : "cursor-pointer hover:brightness-110"
      }`}
    >
      <span
        className={`pointer-events-none inline-block rounded-full bg-white shadow transition-transform duration-200 ${dims.knob} ${
          checked ? dims.on : dims.off
        }`}
      />
    </button>
  );
}

/** Human speed, always in KB/s as requested. */
export function fmtRate(bps) {
  if (!bps || bps < 1) return null;
  return `${(bps / 1024).toFixed(bps < 10240 ? 1 : 0)} KB/s`;
}

/** Human total from bytes. */
function fmtBytes(bytes) {
  if (!bytes || bytes < 1) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function paddedIp(ip) {
  return String(ip)
    .split(".")
    .map((part) => String(parseInt(part, 10)).padStart(3, "0"))
    .join(".");
}

function timeAgo(iso) {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}

function StatusPill({ device }) {
  let cls, Icon, label;
  if (device.watched) {
    cls = "border-cyan-500/30 bg-cyan-500/10 text-cyan-300";
    Icon = Eye;
    label = "Watching";
  } else if (device.blocked) {
    cls = "border-rose-500/30 bg-rose-500/10 text-rose-300";
    Icon = ShieldX;
    label = "Cut off";
  } else if (device.online) {
    cls = "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
    Icon = Wifi;
    label = "Connected";
  } else {
    cls = "border-zinc-700 bg-zinc-800/50 text-zinc-400";
    Icon = WifiOff;
    label = "Away";
  }
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${cls}`}
    >
      <Icon size={13} />
      {label}
    </span>
  );
}

const CB_INPUT =
  "w-28 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 font-mono text-sm text-zinc-100 outline-none focus:border-cyan-500/60";

function RenameModal({ device, onSave, onClose }) {
  const [name, setName] = useState(device.custom_name || "");
  const [icon, setIcon] = useState(device.icon || "");
  const defaultValue = device.icon || "unknown";
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur">
      <div className="w-full max-w-sm rounded-3xl border border-white/10 bg-zinc-900 p-6 shadow-2xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-sky-500/30 bg-sky-500/10">
              <Pencil size={16} className="text-sky-300" />
            </div>
            <div>
              <h3 className="font-semibold leading-none">Name this device</h3>
              <p className="mt-1 text-xs text-zinc-500">{device.ip}</p>
            </div>
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

        <label className="mt-5 block text-xs font-medium text-zinc-400">
          Name — leave empty to go back to "Unknown"
        </label>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Sara's phone"
          maxLength={28}
          className="mt-1.5 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-sky-500/60"
        />

        <label className="mt-4 block text-xs font-medium text-zinc-400">
          Picture
        </label>
        <div className="mt-2 grid grid-cols-6 gap-2">
          <button
            type="button"
            title="No picture"
            onClick={() => setIcon("")}
            className={`flex h-11 items-center justify-center rounded-xl border transition-all ${
              defaultValue === icon
                ? "border-sky-400 bg-sky-500/10 text-sky-300"
                : "border-zinc-700/70 bg-zinc-800/40 text-zinc-500 hover:border-zinc-600"
            }`}
          >
            <X size={16} />
          </button>
          {ICON_LIST.map(({ id, label, Comp }) => {
            const active = icon === id || (!icon && defaultValue === id);
            return (
              <button
                key={id}
                type="button"
                title={label}
                onClick={() => setIcon(id)}
                className={`flex h-11 items-center justify-center rounded-xl border transition-all ${
                  active
                    ? "border-sky-400 bg-sky-500/10 text-sky-300"
                    : "border-zinc-700/70 bg-zinc-800/40 text-zinc-400 hover:border-zinc-600 hover:text-zinc-200"
                }`}
              >
                <Comp size={17} />
              </button>
            );
          })}
        </div>

        <p className="mt-4 text-xs leading-relaxed text-zinc-600">
          The name stays on this computer — the device keeps it until you
          change it, even after restarting.
        </p>
        <button
          type="button"
          onClick={() => onSave(name.trim(), icon)}
          className="mt-5 w-full rounded-xl bg-gradient-to-r from-sky-500 to-cyan-500 py-2.5 font-medium text-black transition-all hover:brightness-110"
        >
          Save
        </button>
      </div>
    </div>
  );
}

function LimitsModal({ device, onSave, onClose }) {
  const [down, setDown] = useState(device.cap_down_kbps ?? "");
  const [up, setUp] = useState(device.cap_up_kbps ?? "");
  const [quota, setQuota] = useState(device.quota_mb ?? "");
  const usedToday = fmtBytes(device.used_today || 0);
  const usedMonth = fmtBytes(device.used_month || 0);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur">
      <div className="w-full max-w-sm rounded-3xl border border-white/10 bg-zinc-900 p-6 shadow-2xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-500/10">
              <Gauge size={17} className="text-cyan-300" />
            </div>
            <div>
              <h3 className="font-semibold leading-none">Limits</h3>
              <p className="mt-1 text-xs text-zinc-500">
                {device.custom_name || device.hostname || device.ip}
              </p>
            </div>
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

        <div className="mt-4 grid grid-cols-2 gap-2 rounded-xl border border-white/5 bg-zinc-950/60 p-3 text-center">
          <div>
            <p className="text-[10px] uppercase tracking-wide text-zinc-500">Today</p>
            <p className="font-mono text-sm text-zinc-200">{usedToday}</p>
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wide text-zinc-500">This month</p>
            <p className="font-mono text-sm text-zinc-200">{usedMonth}</p>
          </div>
        </div>

        <label className="mt-5 block text-xs font-medium text-zinc-400">
          Daily data budget — MB (when it is used up, the device goes offline
          until the next day)
        </label>
        <input
          type="number"
          min="0"
          value={quota}
          onChange={(e) => setQuota(e.target.value)}
          placeholder="no budget"
          className={`${CB_INPUT} mt-1.5`}
        />

        <label className="mt-4 block text-xs font-medium text-zinc-400">
          Download cap — KB/s (leave empty for no limit)
        </label>
        <input
          type="number"
          min="8"
          value={down}
          onChange={(e) => setDown(e.target.value)}
          placeholder="no limit"
          className={`${CB_INPUT} mt-1.5`}
        />

        <label className="mt-4 block text-xs font-medium text-zinc-400">
          Upload cap — KB/s (leave empty for no limit)
        </label>
        <input
          type="number"
          min="8"
          value={up}
          onChange={(e) => setUp(e.target.value)}
          placeholder="no limit"
          className={`${CB_INPUT} mt-1.5`}
        />

        <p className="mt-4 text-xs leading-relaxed text-zinc-600">
          The daily budget counts everything this device used while the app
          metered it and stays effective day after day. The speed caps work
          while the device is being watched and are lifted automatically when
          watching stops.
        </p>
        <button
          type="button"
          onClick={() => {
            const q = parseInt(quota, 10);
            onSave(parseInt(down, 10) || 0, parseInt(up, 10) || 0, Number.isFinite(q) ? q : null);
          }}
          className="mt-5 w-full rounded-xl bg-gradient-to-r from-cyan-500 to-sky-500 py-2.5 font-medium text-black transition-all hover:brightness-110"
        >
          Save limits
        </button>
      </div>
    </div>
  );
}

function UsageCell({ device, spark }) {
  if (!device.watched) {
    return <span className="text-xs text-zinc-600">—</span>;
  }
  const down = device.down_rate || 0;
  const up = device.up_rate || 0;
  const capDown = device.cap_down_kbps;
  const capUp = device.cap_up_kbps;
  const totals = `Since ${timeAgo(device.watched_since)}: received ${fmtBytes(
    device.total_down
  )}, sent ${fmtBytes(device.total_up)}`;
  return (
    <div
      title={totals}
      className="flex flex-col gap-0.5 whitespace-nowrap font-mono text-xs"
    >
      <div className="flex items-center gap-2">
        <span className={down ? "text-emerald-300" : "text-zinc-600"}>
          ↓ {fmtRate(down) || "0 KB/s"}
        </span>
        <span className="text-zinc-700">·</span>
        <span className={up ? "text-sky-300" : "text-zinc-600"}>
          ↑ {fmtRate(up) || "0 KB/s"}
        </span>
      </div>
      {spark && spark.length >= 2 && (
        <Sparkline
          down={spark.map((p) => p.down)}
          up={spark.map((p) => p.up)}
        />
      )}
      {Boolean(capDown || capUp) && (
        <div className="flex items-center gap-1.5 font-sans text-[11px] text-cyan-400/90">
          <Gauge size={11} />
          cap
          {capDown ? ` ↓ ${capDown} KB/s` : ""}
          {capUp ? ` ↑ ${capUp} KB/s` : ""}
        </div>
      )}
      {Boolean(device.quota_mb) && (
        <div
          className={`flex items-center gap-1 font-sans text-[11px] ${
            (device.used_today || 0) >= device.quota_mb * 1024 * 1024
              ? "text-rose-400"
              : "text-emerald-400/90"
          }`}
        >
          <PieChart size={11} />
          budget: {fmtBytes(device.used_today || 0)} / {device.quota_mb} MB
        </div>
      )}
    </div>
  );
}

function WatchButton({ watched, disabled, disabledTitle, onClick, subtleOnly }) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      title={watched ? "Stop watching usage" : disabledTitle || "Watch this device's usage"}
      className={`flex h-9 w-9 items-center justify-center rounded-lg border transition-all ${
        watched
          ? "border-cyan-500/40 bg-cyan-500/10 text-cyan-300 hover:border-cyan-400"
          : subtleOnly
            ? "cursor-not-allowed border-transparent bg-transparent text-transparent"
            : `border-zinc-700/80 bg-zinc-800/50 text-zinc-400 hover:border-zinc-600 hover:text-zinc-200 ${
                disabled ? "cursor-not-allowed opacity-40" : ""
              }`
      }`}
    >
      {watched ? <EyeOff size={16} /> : <Eye size={16} />}
    </button>
  );
}

function DeviceRow({ device, isGateway, isSelf, disabled, disabledTitle, watchDisabled, watchDisabledTitle, onToggle, onWatch, onLimit, onRename, spark }) {
  const name = device.custom_name || device.auto_name
    ? device.custom_name || device.auto_name
    : isSelf
      ? "Your computer"
      : device.hostname || "Unknown device";
  const iconId = device.icon || device.auto_icon
    || (isSelf ? "desktop" : isGateway ? "router" : "");
  const avatar =
    device.watched
      ? "border-cyan-500/30 bg-cyan-500/10 text-cyan-300"
      : device.blocked
        ? "border-rose-500/30 bg-rose-500/10 text-rose-300"
        : device.online
          ? "border-emerald-500/30 bg-gradient-to-br from-emerald-500/15 to-sky-500/10 text-emerald-300"
          : "border-zinc-700/60 bg-zinc-800/50 text-zinc-500";

  return (
    <tr
      className={`border-b border-white/5 transition-colors last:border-0 ${
        device.blocked ? "bg-rose-950/20" : device.watched ? "bg-cyan-950/15" : ""
      } hover:bg-zinc-800/30`}
    >
      <td className="px-5 py-3.5">
        <div className="flex items-center gap-3">
          <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border ${avatar}`}>
            <DeviceIcon icon={iconId} size={19} />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="truncate font-medium text-zinc-100">{name}</span>
              {isSelf && (
                <span className="shrink-0 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-emerald-300">
                  you
                </span>
              )}
              {isGateway && (
                <span className="shrink-0 rounded-full border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-sky-300">
                  router
                </span>
              )}
              <button
                type="button"
                onClick={() => onRename(device)}
                title="Set a name and picture"
                className="ml-0.5 shrink-0 rounded-md p-1 text-zinc-600 transition-colors hover:bg-zinc-700/40 hover:text-zinc-300"
              >
                <Pencil size={12} />
              </button>
            </div>
            <div className="truncate text-xs text-zinc-500">{device.ip}</div>
          </div>
        </div>
      </td>
      <td className="px-5 py-3.5 whitespace-nowrap text-xs text-zinc-500">
        {timeAgo(device.last_seen)}
      </td>
      <td className={`px-5 py-3.5 whitespace-nowrap text-xs ${device.blocked ? "text-rose-300" : "text-zinc-500"}`}>
        {timeAgo(device.last_poisoned)}
      </td>
      <td className="px-5 py-3.5">
        <UsageCell device={device} spark={spark} />
      </td>
      <td className="px-5 py-3.5">
        <StatusPill device={device} />
      </td>
      <td className="px-5 py-3.5">
        <div className="flex items-center justify-end gap-2">
          {device.watched && (
            <button
              type="button"
              onClick={() => onLimit(device)}
              title="Set speed limits"
              className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/40 bg-cyan-500/10 text-cyan-300 transition-all hover:border-cyan-400"
            >
              <Gauge size={16} />
            </button>
          )}
          <WatchButton
            watched={device.watched}
            disabled={watchDisabled}
            disabledTitle={watchDisabledTitle}
            onClick={() => onWatch(device)}
          />
          <Toggle
            checked={device.blocked}
            disabled={disabled}
            disabledTitle={disabledTitle || "Turn on protection first"}
            onChange={() => onToggle(device)}
          />
        </div>
      </td>
    </tr>
  );
}

export default function DeviceTable({ devices, gatewayIp, selfIp, master, privileged, anyBlocked, onToggle, onWatch, onCap, onRename, sparks }) {
  const [capDevice, setCapDevice] = useState(null);
  const [renameDevice, setRenameDevice] = useState(null);
  const rows = [...devices].sort((a, b) =>
    paddedIp(a.ip).localeCompare(paddedIp(b.ip))
  );

  return (
    <>
      {capDevice && (
        <LimitsModal
          device={capDevice}
          onClose={() => setCapDevice(null)}
          onSave={(downKbps, upKbps, quotaMb) => {
            onCap(capDevice.ip, downKbps, upKbps, quotaMb);
            setCapDevice(null);
          }}
        />
      )}
      {renameDevice && (
        <RenameModal
          device={renameDevice}
          onClose={() => setRenameDevice(null)}
          onSave={(name, icon) => {
            onRename(renameDevice.mac, name, icon);
            setRenameDevice(null);
          }}
        />
      )}
      <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-white/5 text-left text-xs uppercase tracking-wider text-zinc-500">
            <th className="px-5 py-3.5 font-medium">Device</th>
            <th className="px-5 py-3.5 font-medium">Last online</th>
            <th className="px-5 py-3.5 font-medium">Cut off</th>
            <th className="px-5 py-3.5 font-medium">Using now</th>
            <th className="px-5 py-3.5 font-medium">Status</th>
            <th className="px-5 py-3.5 text-right font-medium">Control</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((device) => {
            const isGateway = device.ip === gatewayIp;
            const isSelf = device.ip === selfIp;
            // The app refuses to disconnect the router and this computer itself
            const refused = isSelf || isGateway;
            const disabledTitle = isSelf
              ? "You cannot disconnect your own computer"
              : isGateway
                ? "The router cannot be disconnected - it would cut off everyone"
                : "Turn on protection first";
            const watchRefused = isSelf || isGateway;
            let watchDisabledTitle = "Watch this device's usage";
            if (isSelf) watchDisabledTitle = "Your own computer is counted inside the app";
            else if (isGateway) watchDisabledTitle = "The router itself cannot be watched";
            else if (!master) watchDisabledTitle = "Turn on protection first";
            else if (anyBlocked) watchDisabledTitle = "While a device is cut off, watching is paused";
            return (
              <DeviceRow
                key={device.mac + device.ip}
                device={device}
                isGateway={isGateway}
                isSelf={isSelf}
                disabled={!master || !privileged || refused}
                disabledTitle={disabledTitle}
                watchDisabled={!master || !privileged || watchRefused || (anyBlocked && !device.watched)}
                watchDisabledTitle={watchDisabledTitle}
                onToggle={onToggle}
                onWatch={onWatch}
                onLimit={setCapDevice}
                onRename={setRenameDevice}
                spark={(sparks || {})[device.ip]}
              />
            );
          })}
        </tbody>
      </table>

      {rows.length === 0 && (
        <div className="flex flex-col items-center gap-3 py-14 text-zinc-500">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-zinc-800 bg-zinc-800/50">
            <WifiOff size={24} className="text-zinc-500" />
          </div>
          <p className="text-sm text-zinc-400">No devices here yet</p>
          <p className="text-xs text-zinc-600">Press "Find devices" or wait for a device to join your Wi-Fi.</p>
        </div>
      )}
      </div>
    </>
  );
}
