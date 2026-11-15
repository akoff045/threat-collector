import json

import pandas as pd
import pytest

from conftest import FakeSession
from threat_collector import cli, collect, config


def test_missing_key_raises(monkeypatch, tmp_path):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    with pytest.raises(config.ConfigError):
        config.get_api_key(tmp_path / "nope.env")


def test_key_from_dotenv_and_env_wins(monkeypatch, tmp_path):
    env = tmp_path / ".env"
    env.write_text('# comment\nOTX_API_KEY="from-file"\n', encoding="utf-8")
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    assert config.get_api_key(env) == "from-file"
    monkeypatch.setenv("OTX_API_KEY", "from-shell")
    assert config.get_api_key(env) == "from-shell"


def test_collect_without_key_exits_2(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["collect", "--data-dir", str(tmp_path / "d")]) == 2
    assert "OTX_API_KEY is not set" in capsys.readouterr().err


def test_collect_end_to_end_then_incremental(monkeypatch, tmp_path, two_pages):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OTX_API_KEY", "test")
    sessions = [FakeSession([two_pages[0], two_pages[1]]), FakeSession([two_pages[1]])]
    monkeypatch.setattr(collect, "make_session", lambda key, retries=3: sessions.pop(0))
    data = tmp_path / "d"

    assert cli.main(["collect", "--data-dir", str(data)]) == 0
    first = pd.read_csv(data / "raw_iocs.csv")
    assert len(first) == 6
    state = json.loads((data / "state.json").read_text())
    assert "last_run" in state

    # second run is incremental: modified_since sent, no duplicates added
    second_session = sessions[0]
    assert cli.main(["collect", "--data-dir", str(data)]) == 0
    assert second_session.calls[0]["params"]["modified_since"] == state["last_run"]
    assert len(pd.read_csv(data / "raw_iocs.csv")) == 6


def test_analyze_command(tmp_path, capsys):
    data = tmp_path / "d"
    data.mkdir()
    pd.DataFrame({
        "indicator": ["a.com", "b.com", "1.1.1.1", "a.com"],
        "type": ["domain", "domain", "IPv4", "domain"],
        "pulse_name": ["X", "X", "Y", "Y"],
    }).to_csv(data / "raw_iocs.csv", index=False)
    assert cli.main(["analyze", "--data-dir", str(data)]) == 0
    out = capsys.readouterr().out
    assert "Total indicators: 4" in out
    assert (data / "summary.png").stat().st_size > 0


def test_analyze_without_data(tmp_path):
    assert cli.main(["analyze", "--data-dir", str(tmp_path / "empty")]) == 1
