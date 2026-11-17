from django.utils import timezone
from django.conf import settings
from .models import Scan
from .validators import normalize_and_validate, URLValidationError
from .risk_engine import assess
from .providers.base import ProviderResult
from .providers.safe_browsing import SafeBrowsingProvider
from .providers.virustotal import VirusTotalProvider
from .providers.urlhaus import URLhausProvider
from .providers.phishtank import PhishTankProvider
from .providers.dns_rdap import DNSRDAPProvider

_REGISTRY = {
    "safe_browsing": SafeBrowsingProvider,
    "virustotal": VirusTotalProvider,
    "urlhaus": URLhausProvider,
    "phishtank": PhishTankProvider,
    "dns_rdap": DNSRDAPProvider,
}


def _build_providers():
    enabled = set(getattr(settings, "LINKGUARD", {}).get("PROVIDERS_ENABLED", []))
    return [cls() for name, cls in _REGISTRY.items() if name in enabled]


def run_scan(scan: Scan) -> Scan:
    scan.status = Scan.Status.RUNNING
    scan.save(update_fields=["status"])

    try:
        norm = normalize_and_validate(scan.original_url)
    except URLValidationError as e:
        scan.status = Scan.Status.FAILED
        scan.classification = Scan.Classification.ERROR
        scan.error_message = str(e)
        scan.completed_at = timezone.now()
        scan.save()
        return scan

    scan.normalized_url = norm.normalized
    scan.hostname = norm.hostname

    results: list[ProviderResult] = []
    for provider in _build_providers():
        try:
            results.append(provider.check(norm))
        except Exception as e:  # never let one provider kill the scan
            results.append(ProviderResult(provider.name, "error", error=str(e)[:200]))

    assessment = assess(norm, results)

    scan.provider_results = {r.provider: r.as_dict() for r in results}
    scan.indicators = [i.as_dict() for i in assessment.indicators]
    scan.recommendations = assessment.recommendations
    scan.risk_score = assessment.score
    scan.classification = assessment.classification
    scan.domain_info = next(
        (r.details for r in results if r.provider == "dns_rdap"), {}
    )
    scan.status = Scan.Status.COMPLETE
    scan.completed_at = timezone.now()
    scan.save()
    return scan

