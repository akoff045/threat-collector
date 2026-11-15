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


def test_pulse_concentration():
    c = analyze.pulse_concentration(DF)
    assert c["largest_pulse"] == "Y"
    assert c["largest_share"] == 3 / 5
    assert c["top3_share"] == 1.0


def test_tld_share():
    df = pd.DataFrame({"indicator": ["a.online", "b.ONLINE.", "c.com", "1.1.1.1"],
                       "type": ["domain", "hostname", "domain", "IPv4"]})
    share, n = analyze.tld_share(df)
    assert n == 2
    assert round(share["online"], 3) == round(2 / 3, 3)


def test_quality_checks_flags_bad_formats():
    df = pd.DataFrame({
        "indicator": ["d41d8cd98f00b204e9800998ecf8427e", "xyz", "10.0.0.1", "999.1.1.1", "10.0.0.1"],
        "type": ["FileHash-MD5", "FileHash-MD5", "IPv4", "IPv4", "IPv4"],
        "pulse_name": ["A", "A", "A", "A", "A"],
    })
    q = analyze.quality_checks(df)
    assert q["invalid_format"]["FileHash-MD5"] == 1
    assert q["invalid_format"]["IPv4"] == 1
    assert q["duplicates_within_same_pulse"] == 1


def test_svg_bar_panels_is_valid_svg_with_all_labels():
    import xml.etree.ElementTree as ET
    svg = analyze.svg_bar_panels(
        [{"labels": ["a & b", "c"], "values": [10, 5], "title": "P1", "muted": {"c"}},
         {"labels": ["a & b", "c"], "values": [2, 8], "title": "P2"}],
        title="T <1>", subtitle="sub", fmt="{:.0f}%")
    root = ET.fromstring(svg)  # well-formed, special characters escaped
    texts = [t.text for t in root.iter("{http://www.w3.org/2000/svg}text")]
    assert "a & b" in texts and "T <1>" in texts and "10%" in texts
    rects = [r for r in root.iter("{http://www.w3.org/2000/svg}rect")][1:]  # skip background
    assert len(rects) == 4
    assert rects[1].get("fill") == "#C9C6D3"   # muted label
