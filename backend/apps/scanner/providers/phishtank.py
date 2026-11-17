import requests
from django.conf import settings
from .base import ProviderResult


class PhishTankProvider:
    name = "phishtank"
    requires_key = False
    ENDPOINT = "https://checkurl.phishtank.com/checkurl/"

    def check(self, url):
        try:
            timeout = getattr(settings, "LINKGUARD", {}).get("PROVIDER_TIMEOUT", 6)
            data_payload = {"url": url.normalized, "format": "json"}
            api_key = getattr(settings, "LINKGUARD", {}).get("PHISHTANK_KEY", "")
            if api_key:
                data_payload["app_key"] = api_key

            headers = {"User-Agent": "phishtank/LinkGuard-ThreatScanner"}
            r = requests.post(
                self.ENDPOINT,
                data=data_payload,
                headers=headers,
                timeout=timeout,
            )
            r.raise_for_status()
            data = r.json().get("results", {})
            if data.get("in_database") and data.get("valid"):
                return ProviderResult(
                    self.name,
                    "ok",
                    verdict="malicious",
                    score=85,
                    details={"verified": data.get("verified")},
                )
            return ProviderResult(self.name, "ok", verdict="clean")
        except requests.RequestException as e:
            return ProviderResult(self.name, "unavailable", error=str(e)[:200])

