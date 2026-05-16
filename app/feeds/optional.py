from __future__ import annotations

from typing import Any

from app.feeds.base import BaseFeed
from app.models import CVEEntry, ThreatEntry


class OptionalStubFeed(BaseFeed):
    source = "optional-stub"
    url = "https://example.invalid/optional"

    def parse_threat_entries(self, payload: dict[str, Any]) -> list[ThreatEntry]:
        return []

    def parse_cve_entries(self, payload: dict[str, Any]) -> list[CVEEntry]:
        return []
