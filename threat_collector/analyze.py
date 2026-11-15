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


# --- Deeper analysis used by notebooks/analysis.ipynb and REPORT.md ---

DOMAIN_LIKE = ("domain", "hostname")
HASH_PATTERNS = {
    "FileHash-MD5": r"[0-9a-fA-F]{32}",
    "FileHash-SHA1": r"[0-9a-fA-F]{40}",
    "FileHash-SHA256": r"[0-9a-fA-F]{64}",
}
IPV4_PATTERN = r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"


def pulse_concentration(df):
    """How unevenly indicators are spread across pulses."""
    counts = df["pulse_name"].value_counts()
    total = counts.sum()
    return {
        "pulses": int(counts.size),
        "median_per_pulse": float(counts.median()),
        "largest_pulse": counts.index[0],
        "largest_share": float(counts.iloc[0] / total),
        "top3_share": float(counts.head(3).sum() / total),
        "counts": counts,
    }


def type_share(df):
    """Share (0-1) of each indicator type."""
    return df["type"].value_counts(normalize=True)


def tld_share(df, top=10):
    """Share of domains/hostnames by top-level domain."""
    names = df.loc[df["type"].isin(DOMAIN_LIKE), "indicator"].astype(str).str.lower().str.rstrip(".")
    tld = names.str.extract(r"\.([a-z0-9-]+)$")[0]
    return tld.value_counts(normalize=True).head(top), int(tld.nunique())


def quality_checks(df):
    """Duplicates and format validity per indicator type."""
    out = {
        "rows": int(len(df)),
        "duplicate_values": int(df["indicator"].duplicated().sum()),
        "duplicates_within_same_pulse": int(df.duplicated(["indicator", "pulse_name"]).sum()),
        "missing_values": int(df[["indicator", "type"]].isna().sum().sum()),
    }
    invalid = {}
    for t, pat in HASH_PATTERNS.items():
        vals = df.loc[df["type"] == t, "indicator"].astype(str)
        invalid[t] = int((~vals.str.fullmatch(pat)).sum())
    ips = df.loc[df["type"] == "IPv4", "indicator"].astype(str)
    invalid["IPv4"] = int((~ips.str.fullmatch(IPV4_PATTERN)).sum())
    out["invalid_format"] = invalid
    return out


# --- Lightweight SVG bar charts (no plotting dependency, small text files) ---

def _esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def svg_bar_panels(panels, title, subtitle="", fmt="{:,.0f}", accent="#8055E8",
                   muted="#C9C6D3", ink="#101019", grid="#E6E4EC",
                   label_width=300, panel_width=330, row_height=26):
    """Horizontal bar chart(s) as a standalone SVG string.

    panels: list of dicts with keys
        labels  - category names (drawn top to bottom)
        values  - numbers (same length)
        title   - optional panel heading
        muted   - optional set of labels drawn in the muted colour
    All panels share one scale so they can be compared directly.
    """
    vmax = max(max(p["values"]) for p in panels) or 1
    n = max(len(p["labels"]) for p in panels)
    top = 64 if subtitle else 44
    head = 24 if any(p.get("title") for p in panels) else 0
    bar_area = panel_width - 70
    width = label_width + panel_width * len(panels) + 10
    height = top + head + n * row_height + 16
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
           f'viewBox="0 0 {width} {height}" font-family="Inter, Segoe UI, Helvetica, Arial, sans-serif">',
           f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
           f'<text x="12" y="26" font-size="16" fill="{ink}">{_esc(title)}</text>']
    if subtitle:
        out.append(f'<text x="12" y="48" font-size="12.5" fill="#55536A">{_esc(subtitle)}</text>')
    for i, p in enumerate(panels):
        x0 = label_width + i * panel_width
        y0 = top + head
        if p.get("title"):
            out.append(f'<text x="{x0}" y="{top + 14}" font-size="13" fill="{ink}">{_esc(p["title"])}</text>')
        out.append(f'<line x1="{x0}" y1="{y0 - 4}" x2="{x0}" y2="{y0 + n * row_height}" stroke="{grid}"/>')
        for r, (lab, val) in enumerate(zip(p["labels"], p["values"])):
            y = y0 + r * row_height
            w = max(1.5, bar_area * val / vmax)
            color = muted if lab in p.get("muted", set()) else accent
            if i == 0:
                out.append(f'<text x="{label_width - 10}" y="{y + 15}" font-size="12.5" '
                           f'text-anchor="end" fill="{ink}">{_esc(lab)}</text>')
            out.append(f'<rect x="{x0}" y="{y + 4}" width="{w:.1f}" height="{row_height - 10}" '
                       f'rx="3" fill="{color}"><title>{_esc(lab)}: {fmt.format(val)}</title></rect>')
            out.append(f'<text x="{x0 + w + 6:.1f}" y="{y + 15}" font-size="11.5" '
                       f'fill="{ink}">{fmt.format(val)}</text>')
    out.append("</svg>")
    return "\n".join(out) + "\n"
