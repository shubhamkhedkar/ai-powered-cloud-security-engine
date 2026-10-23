from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1, "INFO": 0}[self.value]


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    resource: str
    region: str
    description: str
    remediation: str
    compliance: list[str] = field(default_factory=list)
    service: str = ""
    ai: dict | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


def security_score(findings: list[Finding]) -> int:
    """100 = no findings; decays with weighted severity."""
    penalty = sum(f.severity.weight for f in findings)
    return max(0, round(100 * (1 / (1 + penalty / 25))))
