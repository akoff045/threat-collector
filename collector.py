"""
collector.py: kept so the original command still works.
Equivalent to:  python -m threat_collector collect
"""
import sys

from threat_collector.cli import main

if __name__ == "__main__":
    sys.exit(main(["collect", *sys.argv[1:]]))
