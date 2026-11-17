import socket
from datetime import datetime, timezone
import requests
from django.conf import settings
from .base import ProviderResult


class DNSRDAPProvider:
    """DNS resolution + RDAP (modern WHOIS) registration data."""
    name = "dns_rdap"
    requires_key = False

    def check(self, url):
        details = {"dns": {}, "rdap": {}}
        try:
            details["dns"]["a"] = sorted({i[4][0] for i in socket.getaddrinfo(url.hostname, None)})
        except socket.gaierror:
            details["dns"]["error"] = "NXDOMAIN or resolution failure"
            return ProviderResult(
                self.name, "ok", verdict="suspicious", score=25, details=details
            )

        # RDAP bootstrap for the domain's TLD.
        labels = url.hostname.split(".")
        apex = ".".join(labels[-2:]) if len(labels) >= 2 else url.hostname
        try:
            timeout = getattr(settings, "LINKGUARD", {}).get("PROVIDER_TIMEOUT", 6)
            r = requests.get(
                f"https://rdap.org/domain/{apex}",
                timeout=timeout,
                headers={"Accept": "application/rdap+json"},
            )
            if r.status_code == 200:
                data = r.json()
                events = {
                    e.get("eventAction"): e.get("eventDate")
                    for e in data.get("events", [])
                }
                details["rdap"]["registered"] = events.get("registration")
                details["rdap"]["expires"] = events.get("expiration")
                age_days = None
                if details["rdap"]["registered"]:
                    reg_str = details["rdap"]["registered"].replace("Z", "+00:00")
                    reg = datetime.fromisoformat(reg_str)
                    age_days = (datetime.now(timezone.utc) - reg).days
                details["rdap"]["age_days"] = age_days
                # Very new domains are a mild risk signal.
                score = 30 if age_days is not None and age_days < 30 else 0
                return ProviderResult(
                    self.name, "ok", verdict="clean", score=score, details=details
                )
            details["rdap"]["status"] = r.status_code
        except requests.RequestException as e:
            details["rdap"]["error"] = str(e)[:200]
        return ProviderResult(self.name, "ok", verdict="unknown", details=details)

