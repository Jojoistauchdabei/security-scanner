from __future__ import annotations

import abc
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from app.models import CVEEntry, FeedVersion, ThreatEntry

logger = logging.getLogger(__name__)


class BaseFeed(abc.ABC):
    source: str
    url: str
    rate_limit_seconds: float = 1.0

    def __init__(self, cache_dir: Path, timeout: float = 15.0) -> None:
        self.cache_dir = cache_dir
        self.timeout = timeout
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    @abc.abstractmethod
    def parse_threat_entries(self, payload: dict[str, Any]) -> list[ThreatEntry]:
        return []

    def parse_cve_entries(self, payload: dict[str, Any]) -> list[CVEEntry]:
        return []

    def fetch(self, offline: bool = False) -> tuple[dict[str, Any], FeedVersion]:
        cache_path = self.cache_dir / f"{self.source}.json"
        now = datetime.now(timezone.utc)

        if offline:
            if not cache_path.exists():
                raise FileNotFoundError(f"No cache available for {self.source}")
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
            version = FeedVersion(self.source, "offline-cache", now, len(payload) if isinstance(payload, list) else 1)
            return payload, version

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(self.url, headers={"User-Agent": "security-scanner-mvp/0.1"})
                response.raise_for_status()
            payload = response.json()
            cache_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            version_tag = str(response.headers.get("ETag") or response.headers.get("Last-Modified") or int(now.timestamp()))
            records = len(payload) if isinstance(payload, list) else len(payload.get("data", [])) if isinstance(payload, dict) else 0
            return payload, FeedVersion(self.source, version_tag, now, records)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Feed fetch failed for %s: %s", self.source, exc)
            if cache_path.exists():
                payload = json.loads(cache_path.read_text(encoding="utf-8"))
                return payload, FeedVersion(self.source, "cache-fallback", now, 0)
            raise
