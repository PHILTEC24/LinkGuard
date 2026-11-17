# LinkGuard 🛡️ — Malicious Link & URL Threat Scanner

> **"Don't click blindly. Scan before you trust."**

LinkGuard is a multi-layered link and domain analysis engine engineered to inspect URLs, domains, and web infrastructure without exposing internal networks or users to compromise.

---

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  React + TypeScript + Tailwind CSS (Vite)                       │
│  Scanner · Risk Gauge · Threat Breakdown · History · Education  │
└───────────────────────────────┬─────────────────────────────────┘
                                │ HTTPS / REST / JWT
┌───────────────────────────────▼─────────────────────────────────┐
│  Django 5 + Django REST Framework                               │
│  ┌──────────────┐  ┌────────────────┐  ┌──────────────────────┐ │
│  │ accounts     │  │ scanner        │  │ dashboard            │ │
│  │ JWT auth/user│  │ validate→score │  │ stats & admin        │ │
│  └──────────────┘  └───────┬────────┘  └──────────────────────┘ │
│                            │                                    │
│  ┌─────────────────────────▼──────────────────────────────┐    │
│  │ ScanService (Orchestrator)                              │    │
│  │  validators.py (SSRF Safe) → risk_engine.py → providers │    │
│  └─────────────────────────┬──────────────────────────────┘    │
│                            │                                    │
│  ┌──────────┬──────────┬───▼──────┬──────────┬─────────────┐   │
│  │ Google   │ Virus    │ URLhaus  │ PhishTank│ DNS & RDAP  │   │
│  │ Safe Br. │ Total    │ (abuse.ch)          │ (WHOIS Age) │   │
│  └──────────┴──────────┴──────────┴──────────┴─────────────┘   │
│                                                                 │
│  Celery + Redis (Async Queue & Provider Rate-Limit Cache)      │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                        ┌───────▼────────┐
                        │  PostgreSQL 16 │
                        └────────────────┘
```

---

## 2. Security Architecture & SSRF Protection

The scanner is hardened against common exploit vectors:

1. **Zero Outbound Target Contact by Default:** LinkGuard queries trusted threat intelligence APIs (`Google Safe Browsing`, `VirusTotal`, `URLhaus`, `PhishTank`, `RDAP`) using the target URL as an argument; it **does not** navigate to the attacker's server by default.
2. **SSRF & DNS Rebinding Defenses:**
   - Pre-validation of IP address literals and resolved hostnames against comprehensive RFC-reserved and link-local ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `fc00::/7`, `::1/128`, etc.).
   - Explicit rejection of cloud metadata hosts (`169.254.169.254`, `metadata.google.internal`, etc.).
   - Rejection of embedded authority credentials (`user:pass@host`).
   - `_PinnedHTTPSConnection`: Optional direct probe pins the pre-verified IP socket connection to prevent DNS rebinding between validation and connection.

---

## 3. Quickstart with Docker Compose

Ensure Docker and Docker Compose are installed, then run:

```bash
# 1. Clone & enter workspace
git clone <repo-url> linkguard
cd linkguard

# 2. Configure environment
cp .env.example .env

# 3. Build & start services (Postgres, Redis, Backend, Celery, Frontend)
docker compose up -d --build
```

Access services:
- **Frontend Web UI:** [http://localhost:5173](http://localhost:5173)
- **Django REST API:** [http://localhost:8000/api/](http://localhost:8000/api/)
- **Admin Panel:** [http://localhost:8000/admin/](http://localhost:8000/admin/)

---

## 4. Manual Local Development Setup

### Backend (Python 3.11+)

```bash
cd backend
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
.\venv\Scripts\activate

pip install -r requirements.txt
cp ../.env.example ../.env

python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 0.0.0.0:8000
```

To run security unit tests:
```bash
pytest apps/scanner/tests/test_security.py
```

### Frontend (Node 20+)

```bash
cd frontend
npm install
npm run dev
```

---

## 5. API Reference

### Scan a URL
- **Endpoint:** `POST /api/scans/`
- **Auth:** Optional (Anonymous throttled to 10/hr; Authenticated 60/hr)
- **Payload:**
```json
{
  "url": "https://suspicious-paypa1-login.xyz/auth"
}
```
- **Response:**
```json
{
  "id": "c1f7a0b3-90d1-4475-8120-001099182db1",
  "original_url": "https://suspicious-paypa1-login.xyz/auth",
  "normalized_url": "https://suspicious-paypa1-login.xyz/auth",
  "hostname": "suspicious-paypa1-login.xyz",
  "status": "complete",
  "classification": "critical",
  "risk_score": 87,
  "indicators": [
    {
      "code": "typosquat",
      "label": "Domain closely resembles 'paypal' (edit distance 1)",
      "weight": 25,
      "severity": "high"
    },
    {
      "code": "bad_tld",
      "label": "Frequently-abused TLD '.xyz'",
      "weight": 12,
      "severity": "medium"
    }
  ],
  "provider_results": {
    "safe_browsing": { "provider": "safe_browsing", "status": "ok", "verdict": "clean" },
    "urlhaus": { "provider": "urlhaus", "status": "ok", "verdict": "malicious", "score": 85 }
  },
  "recommendations": [
    "Do not enter credentials, payment details, or personal information.",
    "If you already entered data, change affected passwords and contact your bank."
  ],
  "created_at": "2026-11-17T02:45:00Z"
}
```

---

## 6. What's Included vs. What to Extend

| Feature Area | Included in this Codebase | Future Commercial Extension |
|---|---|---|
| **SSRF & Validation** | Full IP range checking, DNS rebinding socket pinning, normalization | Tor/Proxy egress routing, IPv6 zone index handling |
| **Threat Providers** | Safe Browsing, VirusTotal, URLhaus, PhishTank, RDAP/WHOIS | PhishFeed, AbuseIPDB, AlienVault OTX, CrowdStrike Falcon |
| **Risk Engine** | Levenshtein typosquatting, Punycode, TLDs, subdomains, file ext, age | ML classification model, optical computer vision brand logo match |
| **Frontend UI** | SVG Risk Gauge, animated stage stepper, findings, history, education | Batch CSV drag-and-drop, webhook alerts, browser extension |
| **Authentication** | Django SimpleJWT endpoints (token pair, refresh, user register) | OAuth2 (Google, GitHub SSO), 2FA/TOTP, Enterprise SAML |
| **Async Scans** | Celery tasks + Redis queue support | WebSockets / SSE real-time stream via Django Channels |

