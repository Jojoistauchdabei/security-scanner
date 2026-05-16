from __future__ import annotations

from typing import Protocol

from app.models import ScanResult


class ScannerPlugin(Protocol):
    name: str

    def after_scan(self, result: ScanResult) -> ScanResult: ...
