# security-scanner

Minimaler lokaler Sicherheits-Scanner (MVP) in Python mit **uv**.

## Features

- Python 3.12+
- rekursives Dateiscanning
- chunk-basiertes Hashing (SHA256, MD5, SHA1)
- optionales Fuzzy Hashing (tlsh/ssdeep, wenn installiert)
- parallele Verarbeitung via `ThreadPoolExecutor`
- lokale SQLite-Hashdatenbank (offline-fähig)
- Klassifizierung: `SAFE`, `UNKNOWN`, `SUSPICIOUS`, `MALICIOUS`
- Risiko-Level: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- CLI mit `typer` + farbige Tabellen mit `rich`
- JSON Export
- vorbereitete Hooks: YARA, CVE Mapping, DNS Cache Scanning, KI Analyse
- modulare Feed-Architektur mit Cache, Feed-Versionen und inkrementellen Updates

## Projektstruktur

```text
project/
├── app/
│   ├── cli.py
│   ├── scanner.py
│   ├── database.py
│   ├── hashing.py
│   ├── risk.py
│   ├── models.py
│   ├── updater.py
│   ├── feeds/
│   ├── plugins/
│   └── utils/
├── data/
├── tests/
├── README.md
├── pyproject.toml
└── main.py
```

## Installation mit uv

```bash
uv sync
```

CLI starten:

```bash
uv run security-scanner --help
```

## Schnellstart

1. Datenbank initialisieren (inkl. Beispiel-Hashes):

```bash
uv run security-scanner init-db --db-path data/scanner.db
```

2. Verzeichnis scannen:

```bash
uv run security-scanner scan data/samples --db-path data/scanner.db
```

3. JSON Export:

```bash
uv run security-scanner scan data/samples --db-path data/scanner.db --json-out data/scan-result.json
```

4. Feeds aktualisieren (online):

```bash
uv run security-scanner update-feeds --db-path data/scanner.db --cache-dir data/feed-cache
```

5. Feeds nur offline aus Cache laden:

```bash
uv run security-scanner update-feeds --offline --db-path data/scanner.db --cache-dir data/feed-cache
```

## Vertrauenswürdige Quellen (vorbereitet)

### CVE / Sicherheitslücken
- NVD API: https://nvd.nist.gov/
- CVE.org API: https://www.cve.org/

### Malware / schädliche Hashes
- MalwareBazaar: https://bazaar.abuse.ch/
- ThreatFox: https://threatfox.abuse.ch/

### Schädliche URLs / Domains
- URLHaus: https://urlhaus.abuse.ch/

### Optional vorbereitet
- AlienVault OTX
- CIRCL CVE Search
- GitHub Security Advisories
- OSV.dev API
- CISA Known Exploited Vulnerabilities

## Hinweis zum MVP

- Fokus ist ein minimal lauffähiger lokaler Prototyp.
- Feed-Parser sind robust gegen Fehler und nutzen lokale Cache-Fallbacks.
- Keine Cloud-Pflicht, keine Telemetrie.
