"""Configuration: paths, API settings and secret loading."""
import os
from dataclasses import dataclass
from pathlib import Path

OTX_SUBSCRIBED_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"


class ConfigError(RuntimeError):
    """Raised when required configuration (e.g. the API key) is missing."""


def load_dotenv(path):
    """Minimal .env loader: KEY=VALUE lines, '#' comments, optional quotes.

    Variables already set in the environment take precedence, so a shell
    export always wins over the file.
    """
    path = Path(path)
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass
class Settings:
    data_dir: Path = Path("data")
    page_size: int = 50          # pulses per API page
    max_pages: int = 10          # safety cap on pagination
    timeout: int = 15            # seconds per request
    retries: int = 3             # retries on timeouts / 429 / 5xx

    @property
    def csv_path(self):
        return self.data_dir / "raw_iocs.csv"

    @property
    def state_path(self):
        return self.data_dir / "state.json"

    @property
    def summary_png(self):
        return self.data_dir / "summary.png"


def get_api_key(env_path=".env"):
    """Return the OTX API key from the environment or a .env file."""
    load_dotenv(env_path)
    key = os.environ.get("OTX_API_KEY", "").strip()
    if not key:
        raise ConfigError(
            "OTX_API_KEY is not set. Copy .env.example to .env and add your key "
            "(OTX > Settings > API Integration), or export OTX_API_KEY in your shell."
        )
    return key
