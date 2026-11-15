"""Collection: talk to the OTX API and turn pulses into flat indicator records."""
import logging
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import OTX_SUBSCRIBED_URL

log = logging.getLogger(__name__)

RECORD_FIELDS = [
    "indicator", "type", "pulse_id", "pulse_name", "pulse_author",
    "pulse_created", "pulse_modified", "tags", "malware_families",
    "tlp", "date_collected",
]


def make_session(api_key, retries=3):
    """A requests session with the API key header and retry/backoff on
    timeouts, rate limiting (429) and server errors."""
    session = requests.Session()
    session.headers.update({"X-OTX-API-KEY": api_key, "Accept": "application/json"})
    retry = Retry(
        total=retries,
        backoff_factor=1.0,                 # 1s, 2s, 4s ...
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        respect_retry_after_header=True,
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def iter_pulses(session, page_size=50, max_pages=10, modified_since=None,
                timeout=15, url=OTX_SUBSCRIBED_URL):
    """Yield pulses page by page, following the API's `next` link.

    Stops after `max_pages` pages so a large subscription cannot run forever.
    """
    params = {"limit": page_size}
    if modified_since:
        params["modified_since"] = modified_since
    next_url = url
    pages = 0
    while next_url and pages < max_pages:
        resp = session.get(next_url, params=params, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        pages += 1
        results = data.get("results", [])
        log.info("Page %d: %d pulses", pages, len(results))
        yield from results
        next_url = data.get("next")
        params = None  # the `next` URL already carries the query string
    if next_url:
        log.warning("Stopped after max_pages=%d; more pulses are available.", max_pages)


def _names(items):
    """OTX returns some lists as strings, some as dicts with a 'display_name'."""
    out = []
    for item in items or []:
        if isinstance(item, dict):
            item = item.get("display_name") or item.get("name") or item.get("id")
        if item:
            out.append(str(item))
    return ";".join(out)


def pulse_to_records(pulse, collected_at=None):
    """Flatten one pulse into one record per indicator."""
    collected_at = collected_at or datetime.now(timezone.utc).isoformat()
    base = {
        "pulse_id": pulse.get("id"),
        "pulse_name": pulse.get("name"),
        "pulse_author": pulse.get("author_name"),
        "pulse_created": pulse.get("created"),
        "pulse_modified": pulse.get("modified"),
        "tags": _names(pulse.get("tags")),
        "malware_families": _names(pulse.get("malware_families")),
        "tlp": pulse.get("TLP") or pulse.get("tlp"),
        "date_collected": collected_at,
    }
    records = []
    for ind in pulse.get("indicators", []) or []:
        value = ind.get("indicator")
        if not value:
            continue
        records.append({"indicator": value, "type": ind.get("type"), **base})
    return records


def collect_records(session, **kwargs):
    """Fetch all pulses (within limits) and return flat indicator records."""
    collected_at = datetime.now(timezone.utc).isoformat()
    records = []
    for pulse in iter_pulses(session, **kwargs):
        records.extend(pulse_to_records(pulse, collected_at))
    return records
