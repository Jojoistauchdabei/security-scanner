from pathlib import Path

from app.database import HashDatabase
from app.models import ThreatEntry


def test_lookup_detects_seeded_hash(tmp_path: Path) -> None:
    db_path = tmp_path / "scanner.db"
    db = HashDatabase(db_path)
    db.init_db()

    entry = ThreatEntry(
        sha256="abc",
        md5="def",
        sha1="ghi",
        tlsh=None,
        source="test",
        threat_type="malware",
        malware_family="unit",
        confidence=99,
        first_seen=None,
        tags=[],
        related_cves=[],
    )
    db.upsert_threat_entries([entry], is_safe=False)

    result = db.lookup_hashes("abc", "x", "y")
    assert len(result["malicious"]) == 1
