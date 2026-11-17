import { BookOpen, ShieldCheck } from "lucide-react";

export function EducationPage() {
  return (
    <div className="mx-auto max-w-4xl px-4 py-10">
      <div className="flex items-center gap-3 mb-4">
        <BookOpen className="h-7 w-7 text-cyan-400" />
        <h1 className="text-3xl font-bold text-white">Security Education & Phishing Defense</h1>
      </div>
      <p className="text-slate-400 mb-8">
        Learn the core techniques cyber adversaries use to deceive users and how LinkGuard's heuristic engine detects them.
      </p>

      <div className="grid gap-6 md:grid-cols-2">
        <div className="bg-navy-800 p-6 rounded-2xl border border-navy-700">
          <h2 className="text-xl font-bold text-white mb-2 flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-cyan-950 text-cyan-400 font-mono text-sm">01</span>
            Typosquatting & Lookalike Domains
          </h2>
          <p className="text-slate-300 text-sm leading-relaxed mb-3">
            Attackers register domains closely matching known legitimate brands (e.g. <code>paypa1.com</code> or <code>rnicrosoft.com</code>). Even single character edits or transposed letters can fool the naked eye.
          </p>
          <div className="bg-navy-900 p-3 rounded-xl text-xs font-mono text-slate-300 border border-navy-700/60">
            <strong>LinkGuard Defense:</strong> Calculates Levenshtein edit distance between registered apex labels and protected brand dictionaries.
          </div>
        </div>

        <div className="bg-navy-800 p-6 rounded-2xl border border-navy-700">
          <h2 className="text-xl font-bold text-white mb-2 flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-cyan-950 text-cyan-400 font-mono text-sm">02</span>
            IDN Homograph / Punycode Attacks
          </h2>
          <p className="text-slate-300 text-sm leading-relaxed mb-3">
            Using Cyrillic or Greek characters that look identical to Latin characters (e.g., Cyrillic 'а' vs Latin 'a'). Browsers represent these internally via <code>xn--</code> Punycode prefixes.
          </p>
          <div className="bg-navy-900 p-3 rounded-xl text-xs font-mono text-slate-300 border border-navy-700/60">
            <strong>LinkGuard Defense:</strong> Automatically detects Punycode markers (<code>xn--</code>) and flags potential internationalized character trickery.
          </div>
        </div>

        <div className="bg-navy-800 p-6 rounded-2xl border border-navy-700">
          <h2 className="text-xl font-bold text-white mb-2 flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-cyan-950 text-cyan-400 font-mono text-sm">03</span>
            The "HTTPS = Safe" Myth
          </h2>
          <p className="text-slate-300 text-sm leading-relaxed mb-3">
            A padlock icon only confirms that traffic is encrypted between you and the server — it does NOT mean the recipient is trustworthy! Modern phishing sites almost always obtain free SSL certificates.
          </p>
          <div className="bg-navy-900 p-3 rounded-xl text-xs font-mono text-slate-300 border border-navy-700/60">
            <strong>LinkGuard Defense:</strong> Evaluates domain age, authoritative registrant records (RDAP), and threat intel feeds independently of TLS presence.
          </div>
        </div>

        <div className="bg-navy-800 p-6 rounded-2xl border border-navy-700">
          <h2 className="text-xl font-bold text-white mb-2 flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-cyan-950 text-cyan-400 font-mono text-sm">04</span>
            Server-Side Request Forgery (SSRF)
          </h2>
          <p className="text-slate-300 text-sm leading-relaxed mb-3">
            When security tools scan URLs, attackers attempt to trick the scanner itself into requesting internal services (like AWS metadata <code>169.254.169.254</code> or internal networks).
          </p>
          <div className="bg-navy-900 p-3 rounded-xl text-xs font-mono text-slate-300 border border-navy-700/60">
            <strong>LinkGuard Defense:</strong> Pre-resolution IP validation, CIDR blocklists, DNS rebinding mitigation, and socket IP pinning.
          </div>
        </div>
      </div>

      <div className="mt-8 bg-cyan-950/40 border border-cyan-800/50 p-6 rounded-2xl">
        <h3 className="text-lg font-bold text-cyan-300 mb-2 flex items-center gap-2">
          <ShieldCheck className="h-5 w-5" /> 5 Golden Rules for Checking Suspicious Links
        </h3>
        <ul className="list-disc list-inside text-sm text-slate-200 space-y-2 mt-3">
          <li><strong>Inspect the Apex Domain:</strong> Look at the rightmost two parts before the path (e.g. <code>paypal.security-update.com</code> is registered to <code>security-update.com</code>, NOT PayPal).</li>
          <li><strong>Never enter credentials from email/SMS links:</strong> Open a new tab and navigate to the official portal directly.</li>
          <li><strong>Expand Shortened Links:</strong> Short links (bit.ly, tinyurl) mask the final destination. Always expand them with a scanner.</li>
          <li><strong>Check for Urgent or Threatening Language:</strong> "Account suspended in 24 hours" is a social engineering hallmark.</li>
          <li><strong>Scanners are Advisors, Not Guarantees:</strong> If your intuition says something feels wrong, trust your caution.</li>
        </ul>
      </div>
    </div>
  );
}

