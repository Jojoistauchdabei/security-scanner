from __future__ import annotations

from app.models import ScanResult
from app.plugins.base import ScannerPlugin


class PluginManager:
    def __init__(self, plugins: list[ScannerPlugin] | None = None) -> None:
        self.plugins = plugins or []

    def run_after_scan(self, result: ScanResult) -> ScanResult:
        current = result
        for plugin in self.plugins:
            current = plugin.after_scan(current)
        return current
