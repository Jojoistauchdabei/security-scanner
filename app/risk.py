from __future__ import annotations

from app.models import Classification, RiskLevel


class RiskEngine:
    """Simple deterministic risk engine for MVP classification."""

    def classify(self, malicious_hits: int, safe_hits: int, confidence: int = 0) -> tuple[Classification, RiskLevel]:
        if malicious_hits > 0:
            if confidence >= 90:
                return Classification.MALICIOUS, RiskLevel.CRITICAL
            return Classification.SUSPICIOUS, RiskLevel.HIGH

        if safe_hits > 0:
            return Classification.SAFE, RiskLevel.LOW

        return Classification.UNKNOWN, RiskLevel.MEDIUM
