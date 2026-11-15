import pandas as pd
import pytest

from threat_collector import collect, transform
from conftest import FakeSession


@pytest.mark.parametrize("value,itype,expected", [
    ("Evil-Login.COM.", "domain", "evil-login.com"),
    ("Sub.Example.org", "hostname", "sub.example.org"),
    ("D41D8CD98F00B204E9800998ECF8427E", "FileHash-MD5", "d41d8cd98f00b204e9800998ecf8427e"),
    ("HTTPS://Evil-Login.com/Path?A=1#frag", "URL", "https://evil-login.com/Path?A=1"),
    ("not a url", "URL", "not a url"),
    (" 203.0.113.7 ", "IPv4", "203.0.113.7"),
    ("CVE-2025-0001", "CVE", "CVE-2025-0001"),
])
def test_normalize_indicator(value, itype, expected):
    assert transform.normalize_indicator(value, itype) == expected


def test_clean_dedupes_within_pulse_but_keeps_cross_pulse_overlap(two_pages):
    df = pd.DataFrame(collect.collect_records(FakeSession(two_pages)))
    out = transform.clean(df)
    domains = out[out["type"] == "domain"]
    # "Evil-Login.COM." and "evil-login.com" collapse in p1; p2's copy is kept
    assert sorted(domains["pulse_id"]) == ["p1", "p2"]
    assert len(out) == 6


def test_clean_handles_legacy_csv_without_pulse_id():
    legacy = pd.DataFrame({
        "indicator": ["A.com", "a.com", "b.com"],
        "type": ["domain", "domain", "domain"],
        "pulse_name": ["X", "X", "X"],
        "date_collected": ["t"] * 3,
    })
    out = transform.clean(legacy)
    assert list(out["indicator"]) == ["a.com", "b.com"]


def test_merge_appends_only_new_records(two_pages):
    first = transform.clean(pd.DataFrame(collect.collect_records(FakeSession([two_pages[0]]), max_pages=1)))
    second = pd.DataFrame(collect.collect_records(FakeSession([two_pages[0], two_pages[1]])))
    merged = transform.merge(first, second)
    assert len(merged) == len(first) + 1   # only p3's CVE is new
    # first-seen timestamp is kept for records seen before
    assert merged.iloc[0]["date_collected"] == first.iloc[0]["date_collected"]


def test_merge_with_nothing_existing(two_pages):
    new = pd.DataFrame(collect.collect_records(FakeSession(two_pages)))
    assert len(transform.merge(None, new)) == 6
