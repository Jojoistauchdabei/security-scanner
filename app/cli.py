from __future__ import annotations

import json
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from app.database import HashDatabase
from app.models import Classification, ScanResult
from app.scanner import FileScanner
from app.updater import FeedUpdater

app = typer.Typer(help="Local Security Scanner MVP")
console = Console()

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")


@app.command("init-db")
def init_db(db_path: Path = typer.Option(Path("data/scanner.db"), help="Path to local SQLite DB")) -> None:
    db = HashDatabase(db_path)
    db.init_db()
    db.seed_example_data()
    console.print(f"[green]Database initialized:[/green] {db_path}")


@app.command("scan")
def scan(
    target: Path = typer.Argument(..., exists=True, readable=True, resolve_path=True),
    db_path: Path = typer.Option(Path("data/scanner.db"), help="Path to local SQLite DB"),
    workers: int = typer.Option(4, min=1, help="Number of worker threads"),
    enable_fuzzy: bool = typer.Option(False, help="Enable optional fuzzy hashing"),
    json_out: Path | None = typer.Option(None, help="Optional JSON output file"),
) -> None:
    db = HashDatabase(db_path)
    db.init_db()

    scanner = FileScanner(db, workers=workers, enable_fuzzy=enable_fuzzy)
    results = scanner.scan(target)

    if not results:
        console.print("[yellow]No files found.[/yellow]")
        raise typer.Exit()

    _print_table(results)

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(
            json.dumps(
                [
                    {
                        "path": str(r.path),
                        "size": r.size,
                        "sha256": r.hashes.sha256,
                        "md5": r.hashes.md5,
                        "sha1": r.hashes.sha1,
                        "fuzzy": r.hashes.fuzzy,
                        "classification": r.classification.value,
                        "risk_level": r.risk_level.value,
                        "source": r.matched_source,
                        "threat_type": r.threat_type,
                        "malware_family": r.malware_family,
                        "confidence": r.confidence,
                        "related_cves": r.related_cves,
                    }
                    for r in results
                ],
                indent=2,
            ),
            encoding="utf-8",
        )
        console.print(f"[cyan]JSON export written:[/cyan] {json_out}")


@app.command("update-feeds")
def update_feeds(
    db_path: Path = typer.Option(Path("data/scanner.db"), help="Path to local SQLite DB"),
    cache_dir: Path = typer.Option(Path("data/feed-cache"), help="Local feed cache directory"),
    offline: bool = typer.Option(False, help="Use local cached feeds only"),
    incremental: bool = typer.Option(True, help="Skip unchanged feed versions"),
) -> None:
    db = HashDatabase(db_path)
    db.init_db()

    updater = FeedUpdater(db, cache_dir=cache_dir)
    stats = updater.update_all(offline=offline, incremental=incremental)

    table = Table(title="Feed Update")
    table.add_column("Source")
    table.add_column("Imported Records", justify="right")
    for source, count in stats.items():
        table.add_row(source, str(count))
    console.print(table)


def _print_table(results: list[ScanResult]) -> None:
    table = Table(title="Scan Results")
    table.add_column("File")
    table.add_column("Classification")
    table.add_column("Risk")
    table.add_column("Source")
    table.add_column("SHA256", overflow="fold")

    for result in results:
        color = _class_color(result.classification)
        table.add_row(
            str(result.path),
            f"[{color}]{result.classification.value}[/{color}]",
            result.risk_level.value,
            result.matched_source or "-",
            result.hashes.sha256,
        )

    console.print(table)


def _class_color(value: Classification) -> str:
    if value == Classification.MALICIOUS:
        return "red"
    if value == Classification.SUSPICIOUS:
        return "yellow"
    if value == Classification.SAFE:
        return "green"
    return "white"
