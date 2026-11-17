import requests
from django.conf import settings
from .base import ProviderResult


class URLhausProvider:
    name = "urlhaus"
    requires_key = False
    ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"

    def check(self, url):
        try:
            timeout = getattr(settings, "LINKGUARD", {}).get("PROVIDER_TIMEOUT", 6)
            headers = {"User-Agent": "LinkGuard-ThreatScanner/1.0"}
            key = getattr(settings, "LINKGUARD", {}).get("URLHAUS_KEY", "")
            if key:
                headers["Auth-Key"] = key

            r = requests.post(
                self.ENDPOINT,
                data={"url": url.normalized},
                headers=headers,
                timeout=timeout,
            )
            r.raise_for_status()
            data = r.json()
            if data.get("query_status") == "ok":
                return ProviderResult(
                    self.name,
                    "ok",
                    verdict="malicious",
                    score=85,
                    details={
                        "threat": data.get("threat"),
                        "tags": data.get("tags"),
                    },
                )
            return ProviderResult(
                self.name,
                "ok",
                verdict="clean",
                details={"query_status": data.get("query_status")},
            )
        except requests.RequestException as e:
            return ProviderResult(self.name, "unavailable", error=str(e)[:200])

