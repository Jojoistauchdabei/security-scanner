from __future__ import annotations

from typing import Any

from app.feeds.base import BaseFeed
from app.models import ThreatEntry


class ThreatFoxFeed(BaseFeed):
    source = "threatfox"
    url = "https://threatfox.abuse.ch/export/json/recent/"

    def parse_threat_entries(self, payload: dict[str, Any]) -> list[ThreatEntry]:
        entries: list[ThreatEntry] = []
        records = payload.get("data", []) if isinstance(payload, dict) else []
        for item in records:
            ioc = item.get("ioc")
            if not isinstance(ioc, str) or len(ioc) < 32:
                continue
            entries.append(
                ThreatEntry(
                    sha256=ioc if len(ioc) == 64 else None,
                    md5=ioc if len(ioc) == 32 else None,
                    sha1=ioc if len(ioc) == 40 else None,
                    tlsh=None,
                    source=self.source,
                    threat_type=item.get("ioc_type"),
                    malware_family=item.get("malware"),
                    confidence=80,
                    first_seen=item.get("first_seen"),
                    tags=[item.get("threat_type", "")] if item.get("threat_type") else [],
                    related_cves=[],
                )
            )
        return entries
