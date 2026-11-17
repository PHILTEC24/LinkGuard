import requests
from django.conf import settings
from .base import ProviderResult


class SafeBrowsingProvider:
    name = "safe_browsing"
    requires_key = True
    ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def check(self, url):
        key = getattr(settings, "LINKGUARD", {}).get("GOOGLE_SAFE_BROWSING_KEY", "")
        if not key:
            return ProviderResult(self.name, "disabled", error="No API key configured.")
        payload = {
            "client": {"clientId": "linkguard", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url.normalized}],
            },
        }
        try:
            timeout = getattr(settings, "LINKGUARD", {}).get("PROVIDER_TIMEOUT", 6)
            r = requests.post(
                self.ENDPOINT,
                params={"key": key},
                json=payload,
                timeout=timeout,
            )
            r.raise_for_status()
            matches = r.json().get("matches", [])
            if matches:
                return ProviderResult(
                    self.name,
                    "ok",
                    verdict="malicious",
                    score=90,
                    details={"matches": matches},
                )
            return ProviderResult(self.name, "ok", verdict="clean", score=0)
        except requests.RequestException as e:
            return ProviderResult(self.name, "unavailable", error=str(e)[:200])

