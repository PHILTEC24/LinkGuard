import base64
import requests
from django.conf import settings
from .base import ProviderResult


class VirusTotalProvider:
    name = "virustotal"
    requires_key = True
    ENDPOINT = "https://www.virustotal.com/api/v3/urls"

    def check(self, url):
        key = getattr(settings, "LINKGUARD", {}).get("VIRUSTOTAL_KEY", "")
        if not key:
            return ProviderResult(self.name, "disabled", error="No API key configured.")
        url_id = base64.urlsafe_b64encode(url.normalized.encode()).decode().strip("=")
        try:
            timeout = getattr(settings, "LINKGUARD", {}).get("PROVIDER_TIMEOUT", 6)
            r = requests.get(
                f"{self.ENDPOINT}/{url_id}",
                headers={"x-apikey": key},
                timeout=timeout,
            )
            if r.status_code == 404:
                return ProviderResult(
                    self.name,
                    "ok",
                    verdict="unknown",
                    details={"note": "URL not previously analyzed by VT."},
                )
            r.raise_for_status()
            stats = (
                r.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(v for v in stats.values() if isinstance(v, int)) or 1
            score = min(100, int((malicious * 100 + suspicious * 40) / total * 2))
            verdict = "malicious" if malicious else ("suspicious" if suspicious else "clean")
            return ProviderResult(
                self.name,
                "ok",
                verdict=verdict,
                score=score,
                details={"stats": stats},
            )
        except requests.RequestException as e:
            return ProviderResult(self.name, "unavailable", error=str(e)[:200])

