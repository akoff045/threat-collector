from conftest import FakeSession

from threat_collector import collect


def test_pagination_follows_next_link(two_pages):
    s = FakeSession(two_pages)
    pulses = list(collect.iter_pulses(s, page_size=2))
    assert [p["id"] for p in pulses] == ["p1", "p2", "p3"]
    assert len(s.calls) == 2
    assert s.calls[0]["params"] == {"limit": 2}
    # the `next` URL carries its own query string
    assert s.calls[1]["params"] is None
    assert "page=2" in s.calls[1]["url"]


def test_max_pages_caps_requests(two_pages):
    s = FakeSession(two_pages)
    pulses = list(collect.iter_pulses(s, max_pages=1))
    assert [p["id"] for p in pulses] == ["p1", "p2"]
    assert len(s.calls) == 1


def test_modified_since_is_sent(two_pages):
    s = FakeSession(two_pages)
    list(collect.iter_pulses(s, page_size=50, modified_since="2025-08-01T00:00:00"))
    assert s.calls[0]["params"]["modified_since"] == "2025-08-01T00:00:00"


def test_pulse_to_records_keeps_pulse_metadata(two_pages):
    pulse = two_pages[0]["results"][0]
    recs = collect.pulse_to_records(pulse, collected_at="2026-01-01T00:00:00+00:00")
    # the empty indicator is skipped
    assert len(recs) == 4
    r = recs[0]
    assert r["pulse_id"] == "p1"
    assert r["pulse_author"] == "AlienVault"
    assert r["tags"] == "phishing;tycoon2fa"
    assert r["malware_families"] == "Tycoon2FA"
    assert r["tlp"] == "white"
    assert set(r) == set(collect.RECORD_FIELDS)


def test_collect_records_flattens_all_pages(two_pages):
    recs = collect.collect_records(FakeSession(two_pages))
    assert len(recs) == 4 + 2 + 1
    assert len({r["date_collected"] for r in recs}) == 1  # one timestamp per run


def test_session_has_key_header_and_retries():
    s = collect.make_session("abc", retries=4)
    assert s.headers["X-OTX-API-KEY"] == "abc"
    adapter = s.get_adapter("https://otx.alienvault.com")
    assert adapter.max_retries.total == 4
    assert 429 in adapter.max_retries.status_forcelist
