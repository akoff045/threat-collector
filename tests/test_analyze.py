import pandas as pd

from threat_collector import analyze

DF = pd.DataFrame({
    "indicator": ["a.com", "b.com", "1.1.1.1", "a.com", "h"],
    "type": ["domain", "domain", "IPv4", "domain", "FileHash-MD5"],
    "pulse_name": ["X", "X", "Y", "Y", "Y"],
})


def test_summarize():
    s = analyze.summarize(DF)
    assert s["total_indicators"] == 5
    assert s["unique_indicators"] == 4
    assert s["pulses"] == 2
    assert s["duplicate_values"] == 1
    assert s["by_type"] == {"domain": 3, "IPv4": 1, "FileHash-MD5": 1}


def test_top_pulses_order():
    assert list(analyze.top_pulses(DF).index) == ["Y", "X"]


def test_plot_writes_png(tmp_path):
    p = analyze.plot_type_counts(DF, tmp_path / "c.png")
    assert p.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
