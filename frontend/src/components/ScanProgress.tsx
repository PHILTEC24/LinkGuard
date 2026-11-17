const STAGES = [
  "Validating URL & blocking unsafe SSRF targets",
  "Resolving DNS records & checking IP ranges",
  "Querying threat intelligence providers",
  "Inspecting domain registration (RDAP/WHOIS)",
  "Computing heuristic risk score & indicators",
];

export function ScanProgress({ active }: { active: number }) {
  return (
    <ul className="space-y-3" aria-live="polite">
      {STAGES.map((label, i) => (
        <li key={label} className="flex items-center gap-3 text-sm">
          <span
            className={`h-2.5 w-2.5 rounded-full ${
              i < active
                ? "bg-cyan-400"
                : i === active
                ? "bg-cyan-400 animate-pulse"
                : "bg-slate-600"
            }`}
          />
          <span className={i <= active ? "text-slate-100" : "text-slate-500"}>
            {label}
          </span>
        </li>
      ))}
    </ul>
  );
}

