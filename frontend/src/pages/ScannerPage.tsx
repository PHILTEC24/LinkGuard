import { useEffect, useState } from "react";
import { ShieldCheck, Loader2, AlertTriangle, ExternalLink, Info, Server } from "lucide-react";
import { api, getApiBaseUrl, setApiBaseUrl } from "../lib/api";
import type { Scan } from "../types";
import { RiskGauge } from "../components/RiskGauge";
import { ScanProgress } from "../components/ScanProgress";

export function ScannerPage() {
  const [url, setUrl] = useState("");
  const [scan, setScan] = useState<Scan | null>(null);
  const [stage, setStage] = useState(-1);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [backendInput, setBackendInput] = useState("");
  const [savedUrl, setSavedUrl] = useState(getApiBaseUrl());

  useEffect(() => {
    if (!loading) return;
    setStage(0);
    const t = setInterval(() => setStage((s) => (s < 4 ? s + 1 : s)), 450);
    return () => clearInterval(t);
  }, [loading]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setScan(null);
    setLoading(true);
    try {
      const result = await api.scan(url);
      setScan(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-3xl px-4 py-10">
      <header className="text-center mb-8">
        <div className="inline-flex items-center gap-2 text-cyan-400 mb-3">
          <ShieldCheck className="h-7 w-7" />
          <span className="font-semibold tracking-wide">LinkGuard Threat Analysis</span>
        </div>
        <h1 className="text-3xl md:text-4xl font-bold text-white">
          Don't click blindly. Scan before you trust.
        </h1>
        <p className="mt-2 text-slate-400">
          Analyze any link against multiple threat-intelligence sources. No scanner
          can guarantee a site is 100% safe — treat results as guidance.
        </p>
      </header>

      <form
        onSubmit={submit}
        className="flex flex-col sm:flex-row gap-3 bg-navy-800 p-4 rounded-2xl shadow-card"
      >
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com/login"
          aria-label="URL to scan"
          className="flex-1 bg-navy-900 text-slate-100 placeholder-slate-500 rounded-xl px-4 py-3 outline-none focus:ring-2 focus:ring-cyan-500"
          required
        />
        <button
          type="submit"
          disabled={loading || !url.trim()}
          className="flex items-center justify-center gap-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-navy-900 font-semibold px-6 py-3 transition cursor-pointer"
        >
          {loading ? (
            <Loader2 className="h-5 w-5 animate-spin" />
          ) : (
            <ShieldCheck className="h-5 w-5" />
          )}
          Scan Link
        </button>
      </form>

      {loading && (
        <div className="mt-6 rounded-2xl bg-navy-800 p-6 shadow-card">
          <ScanProgress active={stage} />
        </div>
      )}

      {error && (
        <div className="mt-6 rounded-xl bg-red-950/50 border border-red-800 p-4 text-red-200">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 mt-0.5 shrink-0" />
            <div className="flex-1">
              <strong>Could not scan:</strong> {error}
              <div className="mt-3 pt-3 border-t border-red-900/60 text-xs text-slate-300">
                <p className="mb-2 flex items-center gap-1.5 font-medium text-slate-300">
                  <Server className="h-3.5 w-3.5 text-cyan-400" /> Current Backend API:
                  <code className="bg-navy-900 px-1.5 py-0.5 rounded text-cyan-300 break-all font-mono">
                    {savedUrl}
                  </code>
                </p>
                <div className="flex flex-col sm:flex-row gap-2 mt-2">
                  <input
                    value={backendInput}
                    onChange={(e) => setBackendInput(e.target.value)}
                    placeholder="e.g. https://linkguard-backend.onrender.com"
                    className="flex-1 bg-navy-900 text-slate-100 placeholder-slate-500 rounded-lg px-3 py-2 text-xs outline-none border border-navy-700 focus:ring-1 focus:ring-cyan-400"
                  />
                  <button
                    type="button"
                    onClick={() => {
                      if (backendInput.trim()) {
                        setApiBaseUrl(backendInput.trim());
                        setSavedUrl(getApiBaseUrl());
                        setError("");
                      }
                    }}
                    className="bg-cyan-500 hover:bg-cyan-400 text-navy-900 font-semibold px-4 py-2 rounded-lg text-xs transition cursor-pointer"
                  >
                    Save & Reconnect
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {scan && <ResultCard scan={scan} />}
    </div>
  );
}

function ResultCard({ scan }: { scan: Scan }) {
  const cls = (scan.classification || "error") as Parameters<
    typeof RiskGauge
  >[0]["classification"];

  return (
    <section className="mt-8 rounded-2xl bg-navy-800 p-6 shadow-card">
      <div className="grid md:grid-cols-[auto,1fr] gap-6 items-center">
        <RiskGauge score={scan.risk_score ?? 0} classification={cls} />
        <div>
          <p className="text-slate-400 text-sm">Scanned URL</p>
          <p className="text-white font-mono break-all text-base font-medium">
            {scan.normalized_url || scan.original_url}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {new Date(scan.created_at).toLocaleString()}
          </p>
        </div>
      </div>

      <div className="mt-6 border-t border-navy-700 pt-6">
        <h3 className="text-white font-semibold flex items-center gap-2">
          <Info className="h-4 w-4 text-cyan-400" /> Findings & Heuristic Indicators
        </h3>
        {scan.indicators.length === 0 ? (
          <p className="text-slate-400 text-sm mt-2">
            No suspicious indicators detected from structural analysis.
          </p>
        ) : (
          <ul className="mt-3 space-y-2">
            {scan.indicators.map((ind) => (
              <li
                key={ind.code}
                className="flex items-start gap-2 text-sm text-slate-200 bg-navy-900/60 p-2.5 rounded-lg border border-navy-700/50"
              >
                <span
                  className={`mt-1 h-2 w-2 rounded-full shrink-0 ${
                    ind.severity === "critical"
                      ? "bg-red-500"
                      : ind.severity === "high"
                      ? "bg-orange-500"
                      : ind.severity === "medium"
                      ? "bg-yellow-500"
                      : "bg-cyan-400"
                  }`}
                />
                <span className="flex-1">
                  {ind.label}
                  <span className="ml-2 text-xs uppercase font-mono text-slate-400">
                    [{ind.severity} • +{ind.weight}pts]
                  </span>
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="mt-6 border-t border-navy-700 pt-6">
        <h3 className="text-white font-semibold">Threat Intelligence Providers</h3>
        <div className="mt-3 grid sm:grid-cols-2 gap-2">
          {Object.values(scan.provider_results).map((p) => (
            <div
              key={p.provider}
              className="flex justify-between items-center rounded-lg bg-navy-900 px-3 py-2 text-sm border border-navy-700/50"
            >
              <span className="text-slate-300 font-medium capitalize">
                {p.provider.replace("_", " ")}
              </span>
              <span
                className={`font-mono text-xs px-2 py-0.5 rounded capitalize ${
                  p.status !== "ok"
                    ? "bg-slate-800 text-slate-400"
                    : p.verdict === "malicious"
                    ? "bg-red-950 text-red-400 border border-red-800"
                    : p.verdict === "suspicious"
                    ? "bg-orange-950 text-orange-400 border border-orange-800"
                    : "bg-green-950 text-green-400 border border-green-800"
                }`}
              >
                {p.status === "ok" ? p.verdict : p.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-6 border-t border-navy-700 pt-6">
        <h3 className="text-white font-semibold">Recommended Actions</h3>
        <ul className="mt-2 list-disc list-inside text-sm text-slate-300 space-y-1">
          {scan.recommendations.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      </div>

      <div className="mt-6 rounded-lg bg-navy-900/40 p-3 border border-navy-700/40 text-xs text-slate-400 flex items-center gap-2">
        <ExternalLink className="h-4 w-4 shrink-0 text-slate-500" />
        <span>
          Risk score is an algorithmic heuristic based on available signals, not a guarantee. Zero-day threats or clean-looking phishing pages may pass undetected.
        </span>
      </div>
    </section>
  );
}

