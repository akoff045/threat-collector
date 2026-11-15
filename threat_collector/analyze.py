"""Analysis: summary statistics and the indicator-type chart."""
import logging

import matplotlib
matplotlib.use("Agg")  # render to files; no display needed
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

log = logging.getLogger(__name__)


def type_counts(df):
    """Number of indicators per type, largest first."""
    return df["type"].value_counts()


def top_pulses(df, n=10):
    """Pulses contributing the most indicators."""
    return df["pulse_name"].value_counts().head(n)


def duplicate_count(df):
    """Indicator values that appear more than once (across or within pulses)."""
    return int(df["indicator"].duplicated().sum())


def summarize(df):
    return {
        "total_indicators": int(len(df)),
        "unique_indicators": int(df["indicator"].nunique()),
        "pulses": int(df["pulse_name"].nunique()),
        "duplicate_values": duplicate_count(df),
        "by_type": type_counts(df).to_dict(),
    }


def plot_type_counts(df, path):
    counts = type_counts(df)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    counts.plot(kind="bar", ax=ax)
    ax.set_title("Indicators by type")
    ax.set_xlabel("Type")
    ax.set_ylabel("Count")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path


def run(csv_path, summary_png):
    df = pd.read_csv(csv_path)
    s = summarize(df)
    print(f"Total indicators: {s['total_indicators']}  "
          f"(unique values: {s['unique_indicators']}, pulses: {s['pulses']})")
    print(type_counts(df).to_string())
    plot_type_counts(df, summary_png)
    print(f"Summary chart saved to {summary_png}")
    return s
