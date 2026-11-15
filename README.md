# Threat Collector

## Overview

Threat Collector is a Python tool that automates the collection of Indicators of Compromise (IOCs) from AlienVault's Open Threat Exchange (OTX). It fetches threat intelligence data, structures it as CSV, and generates a summary chart to support analysis.

## Features

- **Automated IOC collection:** retrieves indicators from the OTX API (`collector.py`).
- **Data processing:** parses and structures threat data into CSV (`data/raw_iocs.csv`).
- **Analytical reporting:** `analyzer.py` prints counts by indicator type and saves a bar chart (`data/summary.png`).
- **Modular design:** collection and analysis are separate scripts.

## Quick start

Requires Python 3.10+ (tested with 3.13) and a free OTX account.

```bash
python -m venv venv
# Windows: venv\Scripts\activate   |   macOS/Linux: source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env              # Windows: copy .env.example .env
# edit .env and set OTX_API_KEY (OTX > Settings > API Integration)

python collector.py               # writes data/raw_iocs.csv
python analyzer.py                # prints a summary, writes data/summary.png
```

You can also skip `.env` and set the key in your shell: `export OTX_API_KEY=...` (PowerShell: `$env:OTX_API_KEY="..."`).

`analyzer.py` works without a key on the CSV already included in `data/`.

## Security

The API key is read from the environment and is never stored in the code. `.env` is listed in `.gitignore`. Never commit it.

## Technologies

- Python
- `requests`: HTTP calls to the OTX API
- `pandas`: data manipulation and CSV handling
- `matplotlib`: charts
