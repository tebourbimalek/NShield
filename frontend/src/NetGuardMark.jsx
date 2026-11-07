/**
 * NetGuardMark - the NetGuard "N + Shield" mark (Concept 2).
 *
 * A shield outline whose interior is the letter N: the left stroke and the
 * right stroke are monochrome, the diagonal that connects them is the cyan
 * accent (the connection being managed). Reads as infrastructure software
 * rather than a consumer security app.
 *
 * - accent defaults to the brand cyan; pass accent={color} to monochrome it.
 * - color defaults to the brand foreground (#E5E7EB).
 */
export default function NetGuardMark({ size = 24, color = "#E5E7EB", accent = "#22D3EE", className = "" }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 512 512"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="NetGuard"
      role="img"
      className={className}
    >
      <path
        d="M256 55 L414 143 V337 L256 457 L98 337 V143 Z"
        stroke={color}
        strokeWidth="25"
        strokeLinejoin="round"
      />
      <path
        d="M174 333 V179"
        stroke={color}
        strokeWidth="27"
        strokeLinecap="square"
      />
      <path
        d="M174 179 L338 333"
        stroke={accent}
        strokeWidth="27"
        strokeLinecap="square"
      />
      <path
        d="M338 333 V179"
        stroke={color}
        strokeWidth="27"
        strokeLinecap="square"
      />
    </svg>
  );
}

export function NetGuardLogo({ size = 48, color = "#E5E7EB", accent = "#22D3EE" }) {
  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: size * 0.28,
      }}
    >
      <NetGuardMark size={size} color={color} accent={accent} />
      <span
        style={{
          color,
          fontFamily: "Geist, Inter, sans-serif",
          fontSize: size * 0.57,
          fontWeight: 650,
          letterSpacing: "-0.045em",
          lineHeight: 1,
        }}
      >
        NetGuard
      </span>
    </div>
  );
}
