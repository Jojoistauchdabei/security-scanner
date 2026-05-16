from __future__ import annotations

import logging
import time
from pathlib import Path

from app.database import HashDatabase
from app.feeds import CVEOrgFeed, MalwareBazaarFeed, NVDFeed, OptionalStubFeed, ThreatFoxFeed, URLHausFeed

logger = logging.getLogger(__name__)


class FeedUpdater:
    """Fetches, caches and normalizes trusted public threat feeds for local usage."""

    def __init__(self, db: HashDatabase, cache_dir: Path) -> None:
        self.db = db
        self.feeds = [
            MalwareBazaarFeed(cache_dir),
            ThreatFoxFeed(cache_dir),
            URLHausFeed(cache_dir),
            NVDFeed(cache_dir),
            CVEOrgFeed(cache_dir),
            OptionalStubFeed(cache_dir),
        ]

    def update_all(self, offline: bool = False, incremental: bool = True) -> dict[str, int]:
        stats: dict[str, int] = {}
        for feed in self.feeds:
            try:
                payload, version = feed.fetch(offline=offline)
                if incremental and self.db.get_feed_version(feed.source) == version.version:
                    stats[feed.source] = 0
                    continue

                threat_entries = feed.parse_threat_entries(payload if isinstance(payload, dict) else {"data": payload})
                cve_entries = feed.parse_cve_entries(payload if isinstance(payload, dict) else {"data": payload})
                inserted = self.db.upsert_threat_entries(threat_entries, is_safe=False)
                self.db.upsert_cve_entries(cve_entries)
                self.db.set_feed_version(version)
                stats[feed.source] = inserted
            except Exception as exc:  # noqa: BLE001
                logger.warning("Feed update failed for %s: %s", feed.source, exc)
                stats[feed.source] = 0
            time.sleep(feed.rate_limit_seconds)
        return stats
