import {
  Gamepad2,
  Headphones,
  Laptop,
  Monitor,
  MonitorSmartphone,
  Printer,
  Router,
  Smartphone,
  Speaker,
  Tablet,
  Tv,
  Watch,
} from "lucide-react";

/**
 * DeviceIcon - friendly device avatars for renamed devices. The id list must
 * stay in sync with ALLOWED_ICONS in the backend.
 */

const MAP = {
  phone: { Comp: Smartphone, label: "Phone" },
  tablet: { Comp: Tablet, label: "Tablet" },
  laptop: { Comp: Laptop, label: "Laptop" },
  desktop: { Comp: Monitor, label: "Desktop" },
  tv: { Comp: Tv, label: "TV" },
  gamepad: { Comp: Gamepad2, label: "Game console" },
  headphones: { Comp: Headphones, label: "Headphones" },
  printer: { Comp: Printer, label: "Printer" },
  router: { Comp: Router, label: "Router" },
  watch: { Comp: Watch, label: "Watch" },
  speaker: { Comp: Speaker, label: "Speaker" },
  unknown: { Comp: MonitorSmartphone, label: "General" },
};

export const ICON_LIST = Object.entries(MAP).map(([id, v]) => ({
  id,
  label: v.label,
  Comp: v.Comp,
}));

export default function DeviceIcon({ icon, size = 19, className = "" }) {
  const entry = MAP[icon] || MAP.unknown;
  const Comp = entry.Comp;
  return <Comp size={size} className={className} />;
}
