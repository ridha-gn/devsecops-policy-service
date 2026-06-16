from typing import List, Optional
from dataclasses import dataclass
from enum import Enum


class PolicySeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class PolicyViolation:
    rule_id: str
    severity: PolicySeverity
    message: str
    line_number: Optional[int] = None
    resource_type: Optional[str] = None
    resource_name: Optional[str] = None
    recommendation: Optional[str] = None


@dataclass
class PolicyDecision:
    allow: bool
    violations: List[PolicyViolation]
    summary: str
    scan_duration_ms: int = 0

    @property
    def is_blocked(self) -> bool:
        return not self.allow

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == PolicySeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == PolicySeverity.HIGH)
