"""
collector.py
Fetch IOCs from a public threat intelligence feed (AlienVault OTX pulses)
and save them to CSV.

The OTX API key is read from the OTX_API_KEY environment variable,
or from a local .env file (see .env.example). Never hard-code it here.
"""
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests

# --- Configuration ---
DATA_DIR = Path("data")
CSV_PATH = DATA_DIR / "raw_iocs.csv"
ENV_PATH = Path(".env")

# Pulses from the OTX accounts you subscribe to (requires an API key)
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"


def load_dotenv(path=ENV_PATH):
    """Minimal .env loader: KEY=VALUE lines, no extra dependency.
    Variables already set in the environment take precedence."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def get_api_key():
    """Return the OTX API key, or exit with a clear message if it is missing."""
    load_dotenv()
    key = os.environ.get("OTX_API_KEY", "").strip()
    if not key:
        sys.exit(
            "OTX_API_KEY is not set. Copy .env.example to .env and add your key "
            "(OTX > Settings > API Integration), or export OTX_API_KEY in your shell."
        )
    return key


def fetch_iocs(api_key, limit=100):
    """Fetch IOC pulses and extract indicators (IPs, domains, URLs, hashes...)."""
    headers = {"X-OTX-API-KEY": api_key}
    resp = requests.get(OTX_URL, params={"limit": limit}, headers=headers, timeout=10)
    resp.raise_for_status()
    data = resp.json()

    collected_at = datetime.now(timezone.utc).isoformat()
    records = []
    for pulse in data.get("results", []):
        for ind in pulse.get("indicators", []):
            records.append({
                "indicator": ind.get("indicator"),
                "type": ind.get("type"),
                "pulse_name": pulse.get("name"),
                "date_collected": collected_at,
            })
    return records


def main():
    api_key = get_api_key()
    DATA_DIR.mkdir(exist_ok=True)
    records = fetch_iocs(api_key, limit=50)
    df = pd.DataFrame(records)
    df.to_csv(CSV_PATH, index=False)
    print(f"Saved {len(df)} indicators to {CSV_PATH}")


if __name__ == "__main__":
    main()
