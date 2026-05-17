from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from app.database import HashDatabase
from app.hashing import calculate_hashes
from app.models import ScanResult
from app.plugins.hooks import AIAnalysisHookPlugin, CVEMappingHookPlugin, DNSCacheHookPlugin, YaraHookPlugin
from app.plugins.manager import PluginManager
from app.risk import RiskEngine

logger = logging.getLogger(__name__)


class FileScanner:
    def __init__(self, db: HashDatabase, workers: int = 4, enable_fuzzy: bool = False) -> None:
        self.db = db
        self.workers = workers
        self.enable_fuzzy = enable_fuzzy
        self.risk_engine = RiskEngine()
        self.plugin_manager = PluginManager(
            plugins=[
                YaraHookPlugin(),
                CVEMappingHookPlugin(),
                DNSCacheHookPlugin(),
                AIAnalysisHookPlugin(),
            ]
        )

    def iter_files(self, target: Path) -> list[Path]:
        if target.is_file():
            return [target]
        return [p for p in target.rglob("*") if p.is_file()]

    def _scan_one(self, path: Path) -> ScanResult:
        logger.debug("Scanning file: %s", path)
        hashes = calculate_hashes(path, enable_fuzzy=self.enable_fuzzy)
        hits = self.db.lookup_hashes(hashes.sha256, hashes.md5, hashes.sha1)

        malicious_hits = len(hits["malicious"])
        safe_hits = len(hits["safe"])
        confidence = max((row["confidence"] for row in hits["malicious"]), default=0)
        classification, risk_level = self.risk_engine.classify(malicious_hits, safe_hits, confidence)

        top_hit = hits["malicious"][0] if hits["malicious"] else hits["safe"][0] if hits["safe"] else None

        result = ScanResult(
            path=path,
            size=path.stat().st_size,
            hashes=hashes,
            classification=classification,
            risk_level=risk_level,
            matched_source=top_hit["source"] if top_hit else None,
            threat_type=top_hit["threat_type"] if top_hit else None,
            malware_family=top_hit["malware_family"] if top_hit else None,
            confidence=top_hit["confidence"] if top_hit else 0,
            related_cves=[],
        )
        return self.plugin_manager.run_after_scan(result)

    def scan(self, target: Path) -> list[ScanResult]:
        files = self.iter_files(target)
        if not files:
            return []

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            return list(executor.map(self._scan_one, files))
