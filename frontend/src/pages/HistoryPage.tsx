import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { Scan } from "../types";
import { Search, ShieldAlert, History } from "lucide-react";

export function HistoryPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [q, setQ] = useState("");
  const [classification, setClassification] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    api.history({ q, classification })
      .then(setScans)
      .catch(() => setScans([]))
      .finally(() => setLoading(false));
  }, [q, classification]);

  return (
    <div className="mx-auto max-w-5xl px-4 py-10">
      <div className="flex items-center gap-3 mb-6">
        <History className="h-7 w-7 text-cyan-400" />
        <h1 className="text-2xl md:text-3xl font-bold text-white">Scan History</h1>
      </div>

      <div className="flex flex-col sm:flex-row gap-3 mb-6">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-3 h-4 w-4 text-slate-500" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search scans by URL or domain…"
            className="w-full bg-navy-800 text-slate-100 placeholder-slate-500 rounded-xl pl-9 pr-4 py-2.5 outline-none focus:ring-2 focus:ring-cyan-500 border border-navy-700"
          />
        </div>
        <select
          value={classification}
          onChange={(e) => setClassification(e.target.value)}
          className="bg-navy-800 text-slate-100 rounded-xl px-4 py-2.5 outline-none focus:ring-2 focus:ring-cyan-500 border border-navy-700"
        >
          <option value="">All risk levels</option>
          <option value="low">Low Risk</option>
          <option value="moderate">Moderate Risk</option>
          <option value="high">High Risk</option>
          <option value="critical">Critical Risk</option>
        </select>
      </div>

      <div className="overflow-x-auto rounded-2xl bg-navy-800 shadow-card border border-navy-700">
        <table className="w-full text-sm">
          <thead className="text-slate-400 text-left bg-navy-900/50">
            <tr>
              <th className="p-4">Normalized URL</th>
              <th className="p-4">Score</th>
              <th className="p-4">Risk Level</th>
              <th className="p-4">Scanned Date</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-navy-700">
            {scans.map((s) => (
              <tr key={s.id} className="hover:bg-navy-700/30 transition">
                <td className="p-4 text-slate-200 font-mono break-all max-w-md">
                  {s.normalized_url || s.original_url}
                </td>
                <td className="p-4 font-bold">
                  <span
                    className={
                      (s.risk_score ?? 0) >= 70
                        ? "text-red-400"
                        : (s.risk_score ?? 0) >= 40
                        ? "text-orange-400"
                        : (s.risk_score ?? 0) >= 20
                        ? "text-yellow-400"
                        : "text-green-400"
                    }
                  >
                    {s.risk_score ?? "—"}
                  </span>
                  <span className="text-slate-500 text-xs">/100</span>
                </td>
                <td className="p-4">
                  <span
                    className={`inline-block px-2.5 py-1 text-xs rounded-full uppercase font-semibold ${
                      s.classification === "critical"
                        ? "bg-red-950 text-red-300 border border-red-800"
                        : s.classification === "high"
                        ? "bg-orange-950 text-orange-300 border border-orange-800"
                        : s.classification === "moderate"
                        ? "bg-yellow-950 text-yellow-300 border border-yellow-800"
                        : "bg-green-950 text-green-300 border border-green-800"
                    }`}
                  >
                    {s.classification || "—"}
                  </span>
                </td>
                <td className="p-4 text-slate-400 whitespace-nowrap">
                  {new Date(s.created_at).toLocaleDateString()} {new Date(s.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </td>
              </tr>
            ))}
            {!loading && scans.length === 0 && (
              <tr>
                <td colSpan={4} className="p-8 text-center text-slate-500">
                  <ShieldAlert className="h-8 w-8 mx-auto mb-2 opacity-40" />
                  No scan history found. Note: Authenticate or perform authenticated scans to persist your user history.
                </td>
              </tr>
            )}
            {loading && (
              <tr>
                <td colSpan={4} className="p-8 text-center text-slate-400">
                  Loading scan records...
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

