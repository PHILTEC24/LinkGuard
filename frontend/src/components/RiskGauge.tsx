import type { Classification } from "../types";

const COLORS: Record<Classification, string> = {
  low: "#22c55e",
  moderate: "#eab308",
  high: "#f97316",
  critical: "#ef4444",
  error: "#64748b",
};

export function RiskGauge({
  score,
  classification,
}: {
  score: number;
  classification: Classification;
}) {
  const r = 80;
  const circumference = Math.PI * r; // half-circle
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const color = COLORS[classification] ?? COLORS.error;

  return (
    <div
      className="flex flex-col items-center"
      role="img"
      aria-label={`Risk score ${score} out of 100, ${classification}`}
    >
      <svg viewBox="0 0 200 110" className="w-64">
        <path
          d={`M20 100 A ${r} ${r} 0 0 1 180 100`}
          fill="none"
          stroke="#1e293b"
          strokeWidth="16"
          strokeLinecap="round"
        />
        <path
          d={`M20 100 A ${r} ${r} 0 0 1 180 100`}
          fill="none"
          stroke={color}
          strokeWidth="16"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - pct)}
          style={{ transition: "stroke-dashoffset 900ms ease" }}
        />
        <text
          x="100"
          y="88"
          textAnchor="middle"
          className="fill-white text-3xl font-bold"
        >
          {score}
        </text>
        <text
          x="100"
          y="104"
          textAnchor="middle"
          className="fill-slate-400 text-xs"
        >
          / 100
        </text>
      </svg>
      <span
        className="mt-2 uppercase tracking-widest text-sm font-semibold"
        style={{ color }}
      >
        {classification} risk
      </span>
    </div>
  );
}

