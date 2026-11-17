"""
Heuristic risk scoring. Each indicator adds weighted points; the total is
capped at 100. This is NOT a probability of compromise.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import ipaddress
import re
from urllib.parse import urlsplit
from django.conf import settings

# Brands commonly impersonated. Lowercased, no TLD.
_PROTECTED_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "outlook", "office365", "binance", "coinbase",
    "metamask", "chase", "wellsfargo", "hsbc", "dhl", "fedex", "linkedin",
]
_SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "club", "click", "link", "live",
    "work", "gq", "tk", "ml", "cf", "ga", "rest", "buzz"
}
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"
}


@dataclass
class Indicator:
    code: str
    label: str
    weight: int
    severity: str  # info | low | medium | high | critical

    def as_dict(self):
        return {
            "code": self.code,
            "label": self.label,
            "weight": self.weight,
            "severity": self.severity,
        }


@dataclass
class RiskAssessment:
    score: int
    classification: str
    indicators: list[Indicator] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def as_dict(self):
        return {
            "score": self.score,
            "classification": self.classification,
            "indicators": [i.as_dict() for i in self.indicators],
            "recommendations": self.recommendations,
        }


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _classify(score: int) -> str:
    default_thresholds = {"low": 20, "moderate": 40, "high": 70}
    t = getattr(settings, "LINKGUARD", {}).get("SCORE_THRESHOLDS", default_thresholds)
    if score >= t["high"]:
        return "critical"
    if score >= t["moderate"]:
        return "high"
    if score >= t["low"]:
        return "moderate"
    return "low"


def assess(url, provider_results: list) -> RiskAssessment:
    indicators: list[Indicator] = []
    recommendations: list[str] = []
    host = url.hostname or ""
    parts = urlsplit(url.normalized)

    # ---- Structural URL checks ----
    if not url.resolves:
        indicators.append(Indicator("unreachable", "Domain does not resolve", 20, "medium"))
    if url.scheme != "https":
        indicators.append(Indicator("no_https", "No HTTPS encryption", 8, "low"))

    if len(url.normalized) > 120:
        indicators.append(Indicator("long_url", "Unusually long URL", 5, "low"))
    if url.normalized.count("?") > 1 or url.query.count("=") > 5:
        indicators.append(Indicator("param_flood", "Excessive URL parameters", 8, "medium"))
    if "@" in parts.netloc:
        indicators.append(Indicator("userinfo", "Credentials embedded in URL", 25, "high"))
    if re.search(r"%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}", url.normalized):
        indicators.append(Indicator("encoding", "Heavy percent-encoding", 10, "medium"))

    # Bare IP host
    try:
        ipaddress.ip_address(host)
        indicators.append(Indicator("ip_host", "URL uses a raw IP address", 20, "high"))
    except ValueError:
        pass

    # Subdomain depth
    labels = host.split(".")
    if len(labels) > 4:
        indicators.append(Indicator("deep_subdomain", "Unusually deep subdomain chain", 10, "medium"))

    # Suspicious TLD
    tld = labels[-1] if labels else ""
    if tld in _SUSPICIOUS_TLDS:
        indicators.append(Indicator("bad_tld", f"Frequently-abused TLD '.{tld}'", 12, "medium"))

    # Brand lookalike in a *non-brand* registrable domain
    apex = ".".join(labels[-2:]) if len(labels) >= 2 else host
    apex_label = labels[-2] if len(labels) >= 2 else host
    for brand in _PROTECTED_BRANDS:
        if brand in host and brand not in apex_label:
            indicators.append(Indicator(
                "brand_subdomain",
                f"Brand name '{brand}' appears in subdomain, not registrable domain",
                18,
                "high",
            ))
            break
        dist = _levenshtein(apex_label, brand)
        if 1 <= dist <= 2 and len(brand) >= 5:
            indicators.append(Indicator(
                "typosquat",
                f"Domain closely resembles '{brand}' (edit distance {dist})",
                25,
                "high",
            ))
            break

    # Punycode / homograph hint
    if "xn--" in host:
        indicators.append(Indicator("punycode", "Punycode/IDN domain may hide lookalike characters", 22, "high"))

    # Shortener
    if apex in _SHORTENERS:
        indicators.append(Indicator("shortener", "URL is shortened; true destination hidden", 15, "medium"))
        recommendations.append("Expand the shortened link with a trusted link expander before visiting.")

    # Double extension in path
    if re.search(r"\.(exe|scr|apk|zip|rar|js|hta)($|\?)", parts.path, re.I):
        indicators.append(Indicator("dangerous_file", "Link points to a potentially executable file", 20, "high"))

    # ---- Provider signals ----
    for pr in provider_results:
        if pr.status != "ok":
            continue
        if pr.verdict == "malicious":
            indicators.append(Indicator(
                f"{pr.provider}_malicious",
                f"{pr.provider} reports this URL as malicious",
                max(40, pr.score),
                "critical",
            ))
        elif pr.verdict == "suspicious":
            indicators.append(Indicator(
                f"{pr.provider}_suspicious",
                f"{pr.provider} reports suspicious signals",
                max(20, pr.score),
                "high",
            ))
        elif pr.provider == "dns_rdap":
            age = pr.details.get("rdap", {}).get("age_days")
            if age is not None and age < 30:
                indicators.append(Indicator(
                    "new_domain",
                    f"Domain registered {age} day(s) ago",
                    15,
                    "medium",
                ))

    score = min(100, sum(i.weight for i in indicators))
    classification = _classify(score)

    # Recommendations
    if classification in ("critical", "high"):
        recommendations += [
            "Do not enter credentials, payment details, or personal information.",
            "If you already entered data, change affected passwords and contact your bank.",
        ]
    elif classification == "moderate":
        recommendations.append(
            "Verify the organization through an independent channel (official app, phone) before proceeding."
        )
    else:
        recommendations.append(
            "No strong indicators found, but scanners cannot guarantee safety — remain cautious."
        )

    recommendations.append(
        "HTTPS alone does not prove a site is legitimate; check the exact domain spelling."
    )
    return RiskAssessment(
        score=score,
        classification=classification,
        indicators=indicators,
        recommendations=recommendations,
    )

