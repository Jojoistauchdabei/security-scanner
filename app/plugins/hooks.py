from __future__ import annotations

from app.models import ScanResult


class YaraHookPlugin:
    name = "yara-hook"

    def after_scan(self, result: ScanResult) -> ScanResult:
        return result


class CVEMappingHookPlugin:
    name = "cve-mapping-hook"

    def after_scan(self, result: ScanResult) -> ScanResult:
        return result


class DNSCacheHookPlugin:
    name = "dns-cache-hook"

    def after_scan(self, result: ScanResult) -> ScanResult:
        return result


class AIAnalysisHookPlugin:
    name = "ai-analysis-hook"

    def after_scan(self, result: ScanResult) -> ScanResult:
        return result
