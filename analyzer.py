"""
analyzer.py
Basic stats & visualization of collected IOCs.
"""
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

DATA_DIR = Path("data")
CSV_PATH = DATA_DIR / "raw_iocs.csv"
SUMMARY_IMG = DATA_DIR / "summary.png"

def main():
    df = pd.read_csv(CSV_PATH)
    print(f"Total indicators: {len(df)}")
    print(df["type"].value_counts())

    # Bar chart of indicator types
    type_counts = df["type"].value_counts()
    type_counts.plot(kind="bar")
    plt.title("Indicators by Type")
    plt.xlabel("Type")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(SUMMARY_IMG)
    print(f"Summary chart saved to {SUMMARY_IMG}")

if __name__ == "__main__":
    main()
