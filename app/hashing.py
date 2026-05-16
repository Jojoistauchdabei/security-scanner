from __future__ import annotations

import hashlib
from pathlib import Path

from app.models import FileHashes

CHUNK_SIZE = 1024 * 1024


def _calculate_fuzzy(path: Path) -> str | None:
    data = path.read_bytes()
    try:
        import tlsh  # type: ignore

        return str(tlsh.hash(data))
    except Exception:
        pass

    try:
        import ssdeep  # type: ignore

        return str(ssdeep.hash(data))
    except Exception:
        return None


def calculate_hashes(path: Path, enable_fuzzy: bool = False) -> FileHashes:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)

    fuzzy = _calculate_fuzzy(path) if enable_fuzzy else None
    return FileHashes(
        sha256=sha256.hexdigest(),
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        fuzzy=fuzzy,
    )
