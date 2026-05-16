from app.models import Classification, RiskLevel
from app.risk import RiskEngine


def test_risk_engine_malicious() -> None:
    classification, risk = RiskEngine().classify(malicious_hits=1, safe_hits=0, confidence=95)
    assert classification == Classification.MALICIOUS
    assert risk == RiskLevel.CRITICAL


def test_risk_engine_unknown() -> None:
    classification, risk = RiskEngine().classify(malicious_hits=0, safe_hits=0, confidence=0)
    assert classification == Classification.UNKNOWN
    assert risk == RiskLevel.MEDIUM
