#!/usr/bin/env python3
"""
Standalone Fitbit token refresh command.

Usage:
    python refresh_tokens.py
    python refresh_tokens.py --force
    python refresh_tokens.py --max-age-hours 6
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fitbit_api import FitbitAuthError
from fitbit_api import FitbitClient
from fitbit_api import FitbitReauthRequiredError

DEFAULT_MAX_AGE_HOURS = FitbitClient.REFRESH_MAX_AGE_HOURS


def main(argv=None):
    """Refresh Fitbit tokens when due or when forced."""
    parser = argparse.ArgumentParser(description="Refresh Fitbit OAuth tokens")
    parser.add_argument("--force", action="store_true", help="Refresh immediately even if tokens are current")
    parser.add_argument(
        "--max-age-hours",
        type=int,
        default=DEFAULT_MAX_AGE_HOURS,
        help="Refresh when the last successful rotation is older than this many hours",
    )
    args = parser.parse_args(argv)

    try:
        client = FitbitClient()
        refreshed = client.refresh_access_token(
            force=args.force,
            max_age_hours=args.max_age_hours,
        )
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    except FitbitReauthRequiredError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    except FitbitAuthError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    if refreshed:
        print("Fitbit tokens refreshed.", file=sys.stderr)
    else:
        print("Fitbit tokens are current; refresh skipped.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
