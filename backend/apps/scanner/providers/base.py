from __future__ import annotations
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class ProviderResult:
    provider: str
    status: str               # "ok" | "unavailable" | "error" | "disabled"
    verdict: str = "unknown"  # "clean" | "suspicious" | "malicious" | "unknown"
    score: int = 0            # 0..100 contribution hint
    details: dict = field(default_factory=dict)
    error: str = ""

    def as_dict(self):
        return {
            "provider": self.provider,
            "status": self.status,
            "verdict": self.verdict,
            "score": self.score,
            "details": self.details,
            "error": self.error,
        }


class ThreatProvider(Protocol):
    name: str
    requires_key: bool

    def check(self, url) -> ProviderResult:
        ...

