"""The one shared result type every rule produces."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str  # "critical" | "high" | "medium" | "low"
    message: str
    location: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "location": self.location,
        }
