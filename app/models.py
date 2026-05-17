from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class Classification(str, Enum):
    SAFE = "SAFE"
    UNKNOWN = "UNKNOWN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(slots=True)
class FileHashes:
    sha256: str
    md5: str
    sha1: str
    fuzzy: str | None = None


@dataclass(slots=True)
class ScanResult:
    path: Path
    size: int
    hashes: FileHashes
    classification: Classification
    risk_level: RiskLevel
    matched_source: str | None = None
    threat_type: str | None = None
    malware_family: str | None = None
    confidence: int = 0
    related_cves: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ThreatEntry:
    sha256: str | None
    md5: str | None
    sha1: str | None
    tlsh: str | None
    source: str
    threat_type: str | None
    malware_family: str | None
    confidence: int
    first_seen: str | None
    tags: list[str]
    related_cves: list[str]


@dataclass(slots=True)
class CVEEntry:
    cve_id: str
    cvss: float | None
    affected_software: str | None
    affected_versions: str | None
    references: list[str]


@dataclass(slots=True)
class FeedVersion:
    source: str
    version: str
    fetched_at: datetime
    records: int
