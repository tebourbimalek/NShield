/**
 * Sparkline — a tiny graph of a watched device's recent speed.
 * Two soft lines: green = coming in (watching), blue = going out.
 * Pure SVG, no libraries, no axes: it reads at a glance.
 */

const W = 140;
const H = 30;
const PAD = 2;

function pointsFor(series, peak) {
  // At least two points needed to draw a line; flat data still draws.
  const n = series.length;
  if (n < 2) return "";
  const spanX = W / (n - 1);
  return series
    .map((v, i) => {
      const x = i * spanX;
      const y = H - PAD - (v / peak) * (H - PAD * 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}

export default function Sparkline({ down = [], up = [] }) {
  const hasData = down.length >= 2 || up.length >= 2;
  const hasUp = up.some((v) => v > 0);
  if (!hasData) return null;
  // One shared scale so the two lines are comparable. 1 KB/s floor keeps a
  // quiet minute from collapsing into a single flat wall.
  const peak = Math.max(...down, ...up, 1024);
  const downPts = pointsFor(down, peak);
  const upPts = pointsFor(up, peak);
  if (!downPts && !upPts) return null;
  return (
    <svg
      width={W}
      height={H}
      viewBox={`0 0 ${W} ${H}`}
      aria-hidden="true"
      className="block h-[30px] w-[140px] opacity-90"
    >
      <polyline
        points={downPts}
        fill="none"
        stroke="#10b981"
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      {hasUp && (
        <polyline
          points={upPts}
          fill="none"
          stroke="#38bdf8"
          strokeWidth="1.5"
          strokeLinejoin="round"
          strokeLinecap="round"
        />
      )}
    </svg>
  );
}
