from pathlib import Path

from app.hashing import calculate_hashes


def test_hashing_generates_expected_lengths(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.txt"
    file_path.write_text("hello scanner", encoding="utf-8")

    hashes = calculate_hashes(file_path)

    assert len(hashes.sha256) == 64
    assert len(hashes.md5) == 32
    assert len(hashes.sha1) == 40
