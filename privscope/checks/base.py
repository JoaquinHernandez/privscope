"""Base interfaces and data structures for all PrivScope audit modules."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List


class Severity:
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    _ORDER = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}

    @classmethod
    def is_gte(cls, severity: str, min_severity: str) -> bool:
        return cls._ORDER.get(severity, 0) >= cls._ORDER.get(min_severity, 0)


class CheckResult:
    """Encapsulates the output of a single audit rule."""

    def __init__(
        self,
        title: str,
        severity: str,
        description: str,
        findings: List[str],
        remediation: str = "",
    ):
        self.title = title
        self.severity = severity
        self.description = description
        self.findings = findings
        self.remediation = remediation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "findings": self.findings,
            "remediation": self.remediation,
        }


class BaseCheck(ABC):
    """Abstract base class for all audit check modules."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Friendly display name of the check module."""
        pass

    @abstractmethod
    def run(self) -> List[CheckResult]:
        """Execute the security audit logic and return discovered findings."""
        pass
