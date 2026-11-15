"""Command-line interface:  python -m threat_collector {collect,analyze}"""
import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from . import analyze, collect, transform
from .config import ConfigError, Settings, get_api_key

log = logging.getLogger("threat_collector")


def _read_state(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _write_state(path, state):
    Path(path).write_text(json.dumps(state, indent=2), encoding="utf-8")


def cmd_collect(args, settings):
    api_key = get_api_key()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    state = _read_state(settings.state_path)
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")

    modified_since = None if args.full else state.get("last_run")
    if modified_since:
        log.info("Incremental run: pulses modified since %s", modified_since)
    else:
        log.info("Full run")

    session = collect.make_session(api_key, retries=settings.retries)
    new = pd.DataFrame(
        collect.collect_records(
            session,
            page_size=settings.page_size,
            max_pages=args.max_pages,
            modified_since=modified_since,
            timeout=settings.timeout,
        ),
        columns=collect.RECORD_FIELDS,
    )
    existing = pd.read_csv(settings.csv_path) if settings.csv_path.exists() and not args.full else None
    before = 0 if existing is None else len(existing)
    merged = transform.merge(existing, new)
    merged.to_csv(settings.csv_path, index=False)

    state["last_run"] = started
    _write_state(settings.state_path, state)
    print(f"Fetched {len(new)} records; dataset now {len(merged)} rows "
          f"(+{len(merged) - before}) in {settings.csv_path}")
    return 0


def cmd_analyze(args, settings):
    if not settings.csv_path.exists():
        print(f"No data at {settings.csv_path}. Run `collect` first.", file=sys.stderr)
        return 1
    analyze.run(settings.csv_path, settings.summary_png)
    return 0


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data-dir", default="data", help="where CSV/state/charts live (default: data)")
    common.add_argument("-v", "--verbose", action="store_true", help="debug logging")

    p = argparse.ArgumentParser(prog="threat_collector",
                                description="Collect and analyse AlienVault OTX indicators.")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("collect", parents=[common], help="fetch pulses from OTX and update the dataset")
    c.add_argument("--max-pages", type=int, default=Settings.max_pages,
                   help=f"page cap (default {Settings.max_pages})")
    c.add_argument("--full", action="store_true",
                   help="ignore the last run and rebuild the dataset from scratch")
    c.set_defaults(func=cmd_collect)

    a = sub.add_parser("analyze", parents=[common], help="print a summary and save the type chart")
    a.set_defaults(func=cmd_analyze)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    settings = Settings(data_dir=Path(args.data_dir))
    try:
        return args.func(args, settings)
    except ConfigError as e:
        print(e, file=sys.stderr)
        return 2
    except Exception as e:  # network/HTTP errors: one clear line, details with -v
        log.debug("Unhandled error", exc_info=True)
        print(f"Error: {e}", file=sys.stderr)
        return 1
