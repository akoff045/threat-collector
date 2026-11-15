"""Cleaning: normalise indicator values, de-duplicate, merge with earlier runs."""
from urllib.parse import urlsplit, urlunsplit

import pandas as pd

DOMAIN_TYPES = {"domain", "hostname"}
HASH_PREFIX = "FileHash-"
DEDUP_KEY = ["indicator", "type", "pulse_id"]


def normalize_indicator(value, ind_type):
    """Return a canonical form of an indicator so duplicates compare equal.

    - domains/hostnames: lower-case, no trailing dot
    - file hashes: lower-case hex
    - URLs: lower-case scheme and host, fragment removed (path/query kept,
      because they are case-sensitive and often meaningful)
    - everything else: surrounding whitespace removed
    """
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return value
    v = str(value).strip()
    t = ind_type or ""
    if t in DOMAIN_TYPES:
        return v.lower().rstrip(".")
    if t.startswith(HASH_PREFIX):
        return v.lower()
    if t == "URL":
        parts = urlsplit(v)
        if parts.scheme and parts.netloc:
            return urlunsplit((parts.scheme.lower(), parts.netloc.lower(),
                               parts.path, parts.query, ""))
        return v
    return v


def clean(df):
    """Normalise values and drop exact duplicates.

    Duplicates are judged on (indicator, type, pulse_id) when pulse_id is
    known, so the same domain reported by two different pulses is kept twice:
    that overlap is itself useful information for analysis.
    """
    if df.empty:
        return df.copy()
    out = df.copy()
    out["indicator"] = [normalize_indicator(v, t) for v, t in zip(out["indicator"], out["type"])]
    out = out.dropna(subset=["indicator"])
    out = out[out["indicator"].astype(str).str.len() > 0]
    key = [c for c in DEDUP_KEY if c in out.columns]
    if "pulse_id" in key and out["pulse_id"].isna().all():
        key = [c for c in key if c != "pulse_id"] + (["pulse_name"] if "pulse_name" in out.columns else [])
    return out.drop_duplicates(subset=key, keep="first").reset_index(drop=True)


def merge(existing, new):
    """Append newly collected records to earlier ones and de-duplicate,
    keeping the first time each record was seen."""
    if existing is None or existing.empty:
        return clean(new)
    if new is None or new.empty:
        return clean(existing)
    return clean(pd.concat([existing, new], ignore_index=True, sort=False))
