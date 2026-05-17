from __future__ import annotations

from typing import Any

from app.feeds.base import BaseFeed
from app.models import CVEEntry, ThreatEntry


class NVDFeed(BaseFeed):
    source = "nvd"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200"

    def parse_threat_entries(self, payload: dict[str, Any]) -> list[ThreatEntry]:
        return []

    def parse_cve_entries(self, payload: dict[str, Any]) -> list[CVEEntry]:
        out: list[CVEEntry] = []
        vulns = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            metrics = cve.get("metrics", {})
            cvss = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                values = metrics.get(key)
                if values:
                    cvss = values[0].get("cvssData", {}).get("baseScore")
                    break
            refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
            out.append(
                CVEEntry(
                    cve_id=cve_id,
                    cvss=float(cvss) if cvss is not None else None,
                    affected_software=None,
                    affected_versions=None,
                    references=refs,
                )
            )
        return out
