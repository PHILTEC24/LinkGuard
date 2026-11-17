import { BrowserRouter, Routes, Route, Link, Navigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { ScannerPage } from "./pages/ScannerPage";
import { HistoryPage } from "./pages/HistoryPage";
import { EducationPage } from "./pages/EducationPage";

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-navy-900 text-slate-100 flex flex-col justify-between">
        <div>
          <nav className="border-b border-navy-700 bg-navy-900/90 backdrop-blur sticky top-0 z-50">
            <div className="mx-auto max-w-6xl px-4 h-16 flex items-center justify-between">
              <Link to="/" className="flex items-center gap-2 text-cyan-400 font-semibold text-lg hover:text-cyan-300 transition">
                <ShieldCheck className="h-6 w-6" /> LinkGuard
              </Link>
              <div className="flex gap-6 text-sm text-slate-300">
                <Link to="/" className="hover:text-cyan-400 transition font-medium">Scanner</Link>
                <Link to="/history" className="hover:text-cyan-400 transition font-medium">History</Link>
                <Link to="/education" className="hover:text-cyan-400 transition font-medium">Education</Link>
              </div>
            </div>
          </nav>
          <main>
            <Routes>
              <Route path="/" element={<ScannerPage />} />
              <Route path="/history" element={<HistoryPage />} />
              <Route path="/education" element={<EducationPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
        <footer className="mt-16 border-t border-navy-700 py-6 text-center text-xs text-slate-500">
          LinkGuard — Don't click blindly. Scan before you trust. · Results are heuristic guidance, not guarantees.
        </footer>
      </div>
    </BrowserRouter>
  );
}

