from __future__ import annotations

from typing import Any

from app.feeds.base import BaseFeed
from app.models import CVEEntry, ThreatEntry


class CVEOrgFeed(BaseFeed):
    source = "cve-org"
    url = "https://cveawg.mitre.org/api/cve/CVE-2024-0001"

    def parse_threat_entries(self, payload: dict[str, Any]) -> list[ThreatEntry]:
        return []

    def parse_cve_entries(self, payload: dict[str, Any]) -> list[CVEEntry]:
        cve_id = payload.get("cveMetadata", {}).get("cveId") if isinstance(payload, dict) else None
        if not cve_id:
            return []
        refs = []
        containers = payload.get("containers", {})
        cna = containers.get("cna", {}) if isinstance(containers, dict) else {}
        for ref in cna.get("references", []):
            url = ref.get("url")
            if url:
                refs.append(url)
        return [
            CVEEntry(
                cve_id=cve_id,
                cvss=None,
                affected_software=None,
                affected_versions=None,
                references=refs,
            )
        ]
