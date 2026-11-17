import pytest
from apps.scanner.validators import normalize_and_validate, URLValidationError, NormalizedURL
from apps.scanner.risk_engine import assess
from apps.scanner.providers.base import ProviderResult


@pytest.mark.parametrize("bad", [
    "http://localhost/admin",
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",   # AWS metadata
    "http://10.0.0.5/",
    "http://[::1]/",
    "ftp://example.com/file",
    "http://user:pass@example.com/",
])
def test_blocks_ssrf_targets(bad):
    with pytest.raises(URLValidationError):
        normalize_and_validate(bad)


def test_normalizes_missing_scheme():
    n = normalize_and_validate("example.com/path", resolve=False)
    assert n.normalized == "https://example.com/path"
    assert n.hostname == "example.com"


def test_flags_typosquat_and_shortener():
    n = NormalizedURL(
        original="x",
        normalized="https://paypa1.com/",
        scheme="https",
        hostname="paypa1.com",
        port=None,
        path="/",
        query="",
        resolves=True,
    )
    a = assess(n, [])
    codes = {i.code for i in a.indicators}
    assert "typosquat" in codes


def test_malicious_provider_drives_critical():
    n = NormalizedURL(
        original="x",
        normalized="https://evil.example/",
        scheme="https",
        hostname="evil.example",
        port=None,
        path="/",
        query="",
        resolves=True,
    )
    pr = ProviderResult("safe_browsing", "ok", verdict="malicious", score=90)
    a = assess(n, [pr])
    assert a.classification == "critical"
    assert a.score >= 70


def test_unavailable_provider_is_not_fabricated():
    n = NormalizedURL(
        original="x",
        normalized="https://example.com/",
        scheme="https",
        hostname="example.com",
        port=None,
        path="/",
        query="",
        resolves=True,
    )
    pr = ProviderResult("virustotal", "unavailable", error="timeout")
    a = assess(n, [pr])
    # no malicious indicator was invented from a failed provider
    assert not any("malicious" in i.code for i in a.indicators)

