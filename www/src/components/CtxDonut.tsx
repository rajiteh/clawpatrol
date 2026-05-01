// slop.dev-style donut showing context-window usage. Color thresholds
// match slop.dev: red ≥90%, amber 70-89%, blue/cool <70%.

export function CtxDonut({ used, max, size = 18 }: { used?: number; max?: number; size?: number }) {
  if (!used || !max) return null;
  const pct = Math.min(1, used / max);
  const color = pct >= 0.9 ? "#f87171" : pct >= 0.7 ? "#fbbf24" : "#a5b4fc";
  const r = (size - 3) / 2;
  const c = size / 2;
  const circ = 2 * Math.PI * r;
  const off = circ * (1 - pct);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="block">
      <circle cx={c} cy={c} r={r} fill="none" stroke="#e5e5e5" strokeWidth={2.5} />
      <circle
        cx={c}
        cy={c}
        r={r}
        fill="none"
        stroke={color}
        strokeWidth={2.5}
        strokeLinecap="round"
        strokeDasharray={circ}
        strokeDashoffset={off}
        transform={`rotate(-90 ${c} ${c})`}
      />
    </svg>
  );
}
