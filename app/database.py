from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.models import FeedVersion, ThreatEntry


class HashDatabase:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def init_db(self) -> None:
        with self.connect() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS threat_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256 TEXT,
                    md5 TEXT,
                    sha1 TEXT,
                    tlsh TEXT,
                    source TEXT NOT NULL,
                    threat_type TEXT,
                    malware_family TEXT,
                    confidence INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT,
                    tags TEXT NOT NULL DEFAULT '[]',
                    related_cves TEXT NOT NULL DEFAULT '[]',
                    is_safe INTEGER NOT NULL DEFAULT 0,
                    metadata TEXT NOT NULL DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_threat_sha256 ON threat_entries(sha256);
                CREATE INDEX IF NOT EXISTS idx_threat_md5 ON threat_entries(md5);
                CREATE INDEX IF NOT EXISTS idx_threat_sha1 ON threat_entries(sha1);

                CREATE TABLE IF NOT EXISTS feed_versions (
                    source TEXT PRIMARY KEY,
                    version TEXT NOT NULL,
                    fetched_at TEXT NOT NULL,
                    records INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS cve_entries (
                    cve_id TEXT PRIMARY KEY,
                    cvss REAL,
                    affected_software TEXT,
                    affected_versions TEXT,
                    references_json TEXT NOT NULL DEFAULT '[]'
                );
                """
            )

    def seed_example_data(self) -> None:
        eicar = ThreatEntry(
            sha256="275a021bbfb6489e54d471899f7db9d1e273e3bb08cc1573677ee9f4963901f1",
            md5="44d88612fea8a8f36de82e1278abb02f",
            sha1="3395856ce81f2b7382dee72602f798b642f14140",
            tlsh=None,
            source="example-seed",
            threat_type="test-file",
            malware_family="EICAR",
            confidence=100,
            first_seen="2007-01-01",
            tags=["demo", "eicar"],
            related_cves=[],
        )
        safe = ThreatEntry(
            sha256="",
            md5="",
            sha1="",
            tlsh=None,
            source="example-safe",
            threat_type="baseline",
            malware_family=None,
            confidence=100,
            first_seen="2024-01-01",
            tags=["safe"],
            related_cves=[],
        )

        with self.connect() as con:
            con.execute("DELETE FROM threat_entries WHERE source IN ('example-seed', 'example-safe')")
            self.upsert_threat_entries([eicar], is_safe=False, con=con)
            if safe.sha256 or safe.md5 or safe.sha1:
                self.upsert_threat_entries([safe], is_safe=True, con=con)

    def upsert_threat_entries(
        self,
        entries: list[ThreatEntry],
        is_safe: bool = False,
        con: sqlite3.Connection | None = None,
    ) -> int:
        owns_connection = con is None
        if con is None:
            con = self.connect()

        inserted = 0
        try:
            for entry in entries:
                con.execute(
                    """
                    INSERT INTO threat_entries (
                        sha256, md5, sha1, tlsh, source, threat_type, malware_family,
                        confidence, first_seen, tags, related_cves, is_safe, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.sha256,
                        entry.md5,
                        entry.sha1,
                        entry.tlsh,
                        entry.source,
                        entry.threat_type,
                        entry.malware_family,
                        entry.confidence,
                        entry.first_seen,
                        json.dumps(entry.tags),
                        json.dumps(entry.related_cves),
                        1 if is_safe else 0,
                        "{}",
                    ),
                )
                inserted += 1
            con.commit()
        finally:
            if owns_connection:
                con.close()
        return inserted

    def set_feed_version(self, version: FeedVersion) -> None:
        with self.connect() as con:
            con.execute(
                """
                INSERT INTO feed_versions (source, version, fetched_at, records)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    version = excluded.version,
                    fetched_at = excluded.fetched_at,
                    records = excluded.records
                """,
                (
                    version.source,
                    version.version,
                    version.fetched_at.astimezone(timezone.utc).isoformat(),
                    version.records,
                ),
            )

    def get_feed_version(self, source: str) -> str | None:
        with self.connect() as con:
            row = con.execute("SELECT version FROM feed_versions WHERE source = ?", (source,)).fetchone()
            return row["version"] if row else None

    def lookup_hashes(self, sha256: str, md5: str, sha1: str) -> dict[str, list[sqlite3.Row]]:
        with self.connect() as con:
            hits = con.execute(
                """
                SELECT * FROM threat_entries
                WHERE (sha256 = ? AND sha256 <> '') OR (md5 = ? AND md5 <> '') OR (sha1 = ? AND sha1 <> '')
                """,
                (sha256, md5, sha1),
            ).fetchall()

        malicious = [row for row in hits if row["is_safe"] == 0]
        safe = [row for row in hits if row["is_safe"] == 1]
        return {"malicious": malicious, "safe": safe}
