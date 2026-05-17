from __future__ import annotations

from typing import Any

from app.feeds.base import BaseFeed
from app.models import ThreatEntry


class URLHausFeed(BaseFeed):
    source = "urlhaus"
    url = "https://urlhaus.abuse.ch/downloads/json_recent/"

    def parse_threat_entries(self, payload: dict[str, Any]) -> list[ThreatEntry]:
        entries: list[ThreatEntry] = []
        records = payload if isinstance(payload, list) else payload.get("urls", []) if isinstance(payload, dict) else []
        for item in records:
            tags = item.get("tags") if isinstance(item, dict) else []
            entries.append(
                ThreatEntry(
                    sha256=None,
                    md5=None,
                    sha1=None,
                    tlsh=None,
                    source=self.source,
                    threat_type="malicious-url",
                    malware_family=item.get("threat") if isinstance(item, dict) else None,
                    confidence=70,
                    first_seen=item.get("dateadded") if isinstance(item, dict) else None,
                    tags=tags if isinstance(tags, list) else [],
                    related_cves=[],
                )
            )
        return entries
