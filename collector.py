"""
collector.py
Fetch IOCs from a public threat intelligence feed (AlienVault OTX pulses)
and save them to CSV.
"""
import requests
import pandas as pd
from datetime import datetime
from pathlib import Path
# --- Configuration ---
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)
CSV_PATH = DATA_DIR / "raw_iocs.csv"

# Public API endpoint (no API key required for a limited sample)
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"


HEADERS = {"X-OTX-API-KEY":  "7559e9a6eb68e011685b54df2af385fde71cdee23f17bb2392d0e3d3784a1572"}

def fetch_iocs(limit=100):
    """Fetch IOC pulses and extract indicators (IPs, domains, URLs)."""
    resp = requests.get(OTX_URL, params={"limit": limit}, headers=HEADERS, timeout=10)

    resp.raise_for_status()
    data = resp.json()
    
    records = []
    for pulse in data.get("results", []):
        for ind in pulse.get("indicators", []):
            records.append({
                "indicator": ind.get("indicator"),
                "type": ind.get("type"),
                "pulse_name": pulse.get("name"),
                "date_collected": datetime.utcnow().isoformat()
            })
    return records

def main():
    records = fetch_iocs(limit=50)
    df = pd.DataFrame(records)
    df.to_csv(CSV_PATH, index=False)
    print(f"Saved {len(df)} indicators to {CSV_PATH}")
if __name__ == "__main__":
    main()
