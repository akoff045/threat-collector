# Threat Collector

A Python pipeline that collects Indicators of Compromise (IOCs) from AlienVault's Open Threat Exchange (OTX), cleans and de-duplicates them, and produces summary statistics and charts for analysis.

## What it does

| Stage | Module | What happens |
| --- | --- | --- |
| Collect | `threat_collector/collect.py` | Calls the OTX API for pulses (threat reports) from accounts you subscribe to, follows pagination, retries on timeouts/rate limits, and flattens each pulse into one row per indicator, keeping pulse metadata (author, dates, tags, malware families, TLP). |
| Clean | `threat_collector/transform.py` | Normalises values (lower-case domains and hashes, URL fragments removed) and de-duplicates. The same indicator reported by two different pulses is kept, because that overlap is itself useful. |
| Store | `data/raw_iocs.csv` + `data/state.json` | Each run is **incremental**: only pulses modified since the last run are fetched and merged into the existing dataset. |
| Analyze | `threat_collector/analyze.py` | Counts by indicator type, top pulses, duplicate values, and a bar chart (`data/summary.png`). |

## Quick start

Requires Python 3.11+ (tested with 3.13) and a free OTX account.

```bash
python -m venv venv
# Windows: venv\Scripts\activate   |   macOS/Linux: source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env              # Windows: copy .env.example .env
# edit .env and set OTX_API_KEY (OTX > Settings > API Integration)

python -m threat_collector collect            # incremental update of data/raw_iocs.csv
python -m threat_collector analyze            # summary + data/summary.png
```

Options: `collect --full` rebuilds the dataset from scratch, `collect --max-pages N` limits API pages (default 10), `--data-dir DIR` changes where files live, and `-v` turns on debug logging.

The original commands still work: `python collector.py` and `python analyzer.py`.

`analyze` works without a key on the snapshot already included in `data/`.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The tests run against saved API responses in `tests/fixtures/`, so they need no network access or API key.

## Included dataset

`data/raw_iocs.csv` is a snapshot collected on 2025-09-25: 30,343 indicators from 49 pulses. It was collected with the first version of the tool, so it has no pulse metadata columns. Those columns appear in data collected from now on.

## Security

The API key is read from the environment or `.env` and is never stored in the code. `.env` is listed in `.gitignore`.

## Limitations

- The subscribed-pulses endpoint reflects the OTX accounts you follow, not the global threat landscape.
- Indicators are reported as they appear in pulses; the tool does not verify whether they are still malicious.
- CSV storage is simple but not suited to very large datasets.

## Technologies

Python · requests (with urllib3 retries) · pandas · matplotlib · pytest
