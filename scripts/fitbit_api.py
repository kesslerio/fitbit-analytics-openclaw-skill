#!/usr/bin/env python3
"""
Fitbit Web API Wrapper with Auto-Refresh and Token Persistence

Usage:
    python fitbit_api.py activity --days 7
    python fitbit_api.py heartrate --days 7
    python fitbit_api.py sleep --days 7
    python fitbit_api.py report --type weekly
"""

import os
import sys
import json
import argparse
import base64
import fcntl
import hashlib
import stat
import tempfile
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import contextmanager

SKILL_DIR = Path(__file__).parent.parent
SECRETS_PATH = Path.home() / ".config" / "systemd" / "user" / "secrets.conf"
TOKEN_CACHE_PATH = Path.home() / ".fitbit-analytics" / "tokens.json"
TOKEN_LOCK_PATH = Path.home() / ".fitbit-analytics" / "tokens.lock"


class FitbitAuthError(RuntimeError):
    """Base error for Fitbit authentication failures."""


class FitbitReauthRequiredError(FitbitAuthError):
    """Raised when Fitbit requires a new OAuth authorization flow."""


class FitbitClient:
    """Fitbit Web API client with auto-refresh and token persistence"""

    BASE_URL = "https://api.fitbit.com"
    TOKEN_REFRESH_THRESHOLD_HOURS = 1  # Refresh if expires within 1 hour
    REFRESH_MAX_AGE_HOURS = 6
    REFRESH_RETRY_DELAYS_SECONDS = (1, 2, 4)

    def __init__(self, client_id=None, client_secret=None, access_token=None, refresh_token=None):
        self.client_id = client_id or self._load_env_from_secrets("FITBIT_CLIENT_ID")
        self.client_secret = client_secret or self._load_env_from_secrets("FITBIT_CLIENT_SECRET")
        self._explicit_access_token = access_token is not None
        self._explicit_refresh_token = refresh_token is not None
        self._access_token = access_token or self._load_env_from_secrets("FITBIT_ACCESS_TOKEN")
        self._refresh_token = refresh_token or self._load_env_from_secrets("FITBIT_REFRESH_TOKEN")
        self._token_expires_at = None
        self._token_refreshed_at = None
        self._load_token_metadata()

        if not self._access_token:
            raise ValueError("FITBIT_ACCESS_TOKEN not set. Get tokens via OAuth flow.")

        self.headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json"
        }

    def _load_env_from_secrets(self, key):
        """Load env var from secrets.conf if not already set"""
        if os.environ.get(key):
            return os.environ[key]
        if SECRETS_PATH.exists():
            for line in SECRETS_PATH.read_text().split('\n'):
                if '=' in line and key in line:
                    return line.split('=', 1)[1].strip().strip('"')
        return None

    def _load_token_metadata(self):
        """Load token metadata from cache file or JWT decode."""
        self._load_cached_tokens()

        if not self._token_expires_at and self._access_token:
            self._decode_jwt_expiry()

    def _load_cached_tokens(self, allow_override=False):
        """Load the latest persisted tokens and timestamps from cache."""
        if not TOKEN_CACHE_PATH.exists():
            return False

        try:
            data = json.loads(TOKEN_CACHE_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            return False

        access_token = data.get("access_token")
        refresh_token = data.get("refresh_token")
        expires_at = data.get("expires_at")
        refreshed_at = data.get("refreshed_at")

        if access_token and (allow_override or not self._explicit_access_token):
            self._access_token = access_token
        if refresh_token and (allow_override or not self._explicit_refresh_token):
            self._refresh_token = refresh_token
        if expires_at:
            try:
                self._token_expires_at = datetime.fromisoformat(expires_at)
            except ValueError:
                self._token_expires_at = None
        if refreshed_at:
            try:
                self._token_refreshed_at = datetime.fromisoformat(refreshed_at)
            except ValueError:
                self._token_refreshed_at = None
        if self._access_token:
            self.headers = {
                "Authorization": f"Bearer {self._access_token}",
                "Content-Type": "application/json"
            }
        return True

    def _decode_jwt_expiry(self):
        """Decode access token JWT to get expiry timestamp"""
        try:
            payload = self._access_token.split('.')[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            data = json.loads(base64.b64decode(payload))
            exp = data.get("exp")
            if exp:
                self._token_expires_at = datetime.fromtimestamp(exp)
        except (IndexError, json.JSONDecodeError, TypeError):
            self._token_expires_at = None

    def _should_refresh(self):
        """Check if token should be refreshed"""
        if not self._token_expires_at:
            return True
        threshold = datetime.now() + timedelta(hours=self.TOKEN_REFRESH_THRESHOLD_HOURS)
        return self._token_expires_at < threshold

    def _is_refresh_age_exceeded(self, max_age_hours):
        """Check if refresh token rotation age exceeds the desired max age."""
        if not self._token_refreshed_at:
            return True
        age_limit = datetime.now() - timedelta(hours=max_age_hours)
        return self._token_refreshed_at < age_limit

    def _should_refresh_for_rotation(self, max_age_hours):
        """Check if token refresh is due for expiry or rotation age."""
        return self._should_refresh() or self._is_refresh_age_exceeded(max_age_hours)

    @contextmanager
    def _token_lock(self):
        """Serialize token refresh and persistence across processes."""
        TOKEN_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        with TOKEN_LOCK_PATH.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _atomic_write_text(self, path, content):
        """Write file contents atomically with secure permissions."""
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
            os.replace(temp_path, path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def _upsert_secret(self, content, key, value):
        """Insert or replace a quoted env assignment without regex substitution."""
        assignment = f'{key}="{value}"'
        lines = content.splitlines()
        for index, line in enumerate(lines):
            if line.startswith(f"{key}="):
                lines[index] = assignment
                break
        else:
            lines.append(assignment)

        updated = "\n".join(lines)
        if content.endswith("\n") or not content:
            updated += "\n"
        return updated

    def _mask_token(self, value):
        """Return a short fingerprint for audit logs without exposing secrets."""
        if not value:
            return "missing"
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]

    def _log_token_rotation(self):
        """Write a masked audit message for successful token rotation."""
        refreshed_at = self._token_refreshed_at.isoformat() if self._token_refreshed_at else "unknown"
        access_fingerprint = self._mask_token(self._access_token)
        refresh_fingerprint = self._mask_token(self._refresh_token)
        print(
            f"Rotated Fitbit tokens at {refreshed_at} "
            f"(access={access_fingerprint}, refresh={refresh_fingerprint})",
            file=sys.stderr,
        )

    def _save_tokens(self, access_token, refresh_token, expires_in):
        """Save tokens to secrets.conf and cache file"""
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._token_refreshed_at = datetime.now()
        self._token_expires_at = self._token_refreshed_at + timedelta(seconds=expires_in)

        # Update secrets.conf
        if SECRETS_PATH.exists():
            content = SECRETS_PATH.read_text()
            updates = {
                "FITBIT_ACCESS_TOKEN": access_token,
                "FITBIT_REFRESH_TOKEN": refresh_token
            }
            for key, value in updates.items():
                content = self._upsert_secret(content, key, value)
            self._atomic_write_text(SECRETS_PATH, content)

        # Save to cache file
        cache_payload = json.dumps({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": self._token_expires_at.isoformat(),
            "refreshed_at": self._token_refreshed_at.isoformat()
        }, indent=2)
        self._atomic_write_text(TOKEN_CACHE_PATH, cache_payload)
        self.headers["Authorization"] = f"Bearer {self._access_token}"

    def _parse_http_error(self, error):
        """Extract Fitbit error type and message from an HTTPError body."""
        try:
            payload = error.read().decode("utf-8")
        except Exception:
            return None, None

        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return None, payload or None

        errors = data.get("errors")
        if isinstance(errors, list) and errors:
            error_item = errors[0]
            return error_item.get("errorType"), error_item.get("message")
        return None, payload or None

    def refresh_access_token(self, force=False, max_age_hours=None):
        """Refresh access token when due or when forced."""
        with self._token_lock():
            self._load_cached_tokens(allow_override=True)

            if not force:
                if max_age_hours is None:
                    if not self._should_refresh():
                        return False
                elif not self._should_refresh_for_rotation(max_age_hours):
                    return False

            if not self.client_id or not self.client_secret or not self._refresh_token:
                raise FitbitAuthError("Fitbit credentials or refresh token are missing.")

            auth_b64 = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
            data = urllib.parse.urlencode({
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token
            }).encode()

            req = urllib.request.Request(
                "https://api.fitbit.com/oauth2/token",
                data=data,
                headers={
                    "Authorization": f"Basic {auth_b64}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                method="POST"
            )

            for attempt, delay in enumerate(self.REFRESH_RETRY_DELAYS_SECONDS, start=1):
                try:
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        tokens = json.loads(resp.read().decode("utf-8"))
                    access_token = tokens.get("access_token")
                    refresh_token = tokens.get("refresh_token")
                    expires_in = tokens.get("expires_in", 28800)
                    if not access_token or not refresh_token:
                        raise FitbitAuthError("Fitbit refresh response did not include rotated tokens.")

                    self._save_tokens(access_token, refresh_token, expires_in)
                    self._log_token_rotation()
                    return True
                except urllib.error.HTTPError as error:
                    error_type, error_message = self._parse_http_error(error)
                    if error.code == 400 and error_type == "invalid_grant":
                        raise FitbitReauthRequiredError(
                            "Fitbit refresh token is invalid; re-authorization is required."
                        ) from error
                    if error.code in (429, 500, 502, 503, 504) and attempt < len(self.REFRESH_RETRY_DELAYS_SECONDS):
                        time.sleep(delay)
                        continue
                    detail = error_message or error.reason
                    raise FitbitAuthError(
                        f"Fitbit token refresh failed: HTTP {error.code} {detail}"
                    ) from error
                except urllib.error.URLError as error:
                    if attempt < len(self.REFRESH_RETRY_DELAYS_SECONDS):
                        time.sleep(delay)
                        continue
                    raise FitbitAuthError(
                        f"Fitbit token refresh failed after retries: {error.reason}"
                    ) from error

            raise FitbitAuthError("Fitbit token refresh failed after retries.")

    def _request(self, endpoint, date_type="date", allow_retry=True):
        """Make API request with auto-refresh"""
        if self._should_refresh():
            self.refresh_access_token()

        url = f"{self.BASE_URL}/{endpoint}"
        req = urllib.request.Request(url, headers=self.headers)

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 401 and allow_retry:
                self.refresh_access_token(force=True)
                return self._request(endpoint, date_type, allow_retry=False)
            raise

    def get_steps(self, start_date, end_date):
        """Fetch step data"""
        endpoint = f"1/user/-/activities/steps/date/{start_date}/{end_date}.json"
        return self._request(endpoint)

    def get_calories(self, start_date, end_date):
        """Fetch calorie data"""
        endpoint = f"1/user/-/activities/calories/date/{start_date}/{end_date}.json"
        return self._request(endpoint)

    def get_distance(self, start_date, end_date):
        """Fetch distance data"""
        endpoint = f"1/user/-/activities/distance/date/{start_date}/{end_date}.json"
        return self._request(endpoint)

    def get_activity_summary(self, start_date, end_date):
        """Fetch activity summary"""
        endpoint = f"1/user/-/activities/date/{start_date}.json"
        return self._request(endpoint)

    def get_heartrate(self, start_date, end_date):
        """Fetch heart rate data"""
        endpoint = f"1/user/-/activities/heart/date/{start_date}/{end_date}.json"
        return self._request(endpoint)

    def get_sleep(self, start_date, end_date):
        """Fetch sleep data (summary)"""
        endpoint = f"1.2/user/-/sleep/date/{start_date}/{end_date}.json"
        return self._request(endpoint)

    def get_sleep_stages(self, start_date, end_date):
        """Fetch detailed sleep stages"""
        endpoint = f"1.3/user/-/sleep/date/{start_date}/{end_date}.json"
        return self._request(endpoint)

    def get_spo2(self, start_date, end_date):
        """Fetch blood oxygen data"""
        endpoint = f"1/user/-/spo2/date/{start_date}/{end_date}.json"
        return self._request(endpoint)

    def get_weight(self, start_date, end_date):
        """Fetch weight data"""
        endpoint = f"1/user/-/body/weight/date/{start_date}/{end_date}.json"
        return self._request(endpoint)

    def get_active_zone_minutes(self, start_date, end_date):
        """Fetch Active Zone Minutes (AZM) data
        
        Returns AZM breakdown:
        - activeZoneMinutes (total)
        - fatBurnActiveZoneMinutes (1× credit)
        - cardioActiveZoneMinutes (2× credit)
        - peakActiveZoneMinutes (2× credit)
        """
        # Calculate number of days between start and end
        start = datetime.strptime(start_date, "%Y-%m-%d")
        end = datetime.strptime(end_date, "%Y-%m-%d")
        days = (end - start).days + 1
        
        # Use period format: 1d, 7d, 30d, etc.
        period = f"{days}d" if days <= 30 else "30d"
        
        endpoint = f"1/user/-/activities/active-zone-minutes/date/{start_date}/{period}.json"
        return self._request(endpoint)


class FitbitAnalyzer:
    """Analyze Fitbit data"""

    def __init__(self, steps_data=None, hr_data=None, sleep_data=None, activity_data=None):
        self.steps = steps_data or []
        self.hr = hr_data or []
        self.sleep = sleep_data or []
        self.activity = activity_data or []

    def average_metric(self, data, key):
        """Calculate average of a metric"""
        if not data:
            return None
        # Convert to float to handle string values from API
        values = []
        for d in data:
            val = d.get(key)
            if val is not None:
                try:
                    values.append(float(val))
                except (ValueError, TypeError):
                    continue
        return sum(values) / len(values) if values else None

    def trend(self, data, key, days=7):
        """Calculate trend over N days"""
        if len(data) < 2:
            return 0
        recent = data[-days:]
        if len(recent) < 2:
            return 0
        try:
            first = float(recent[0].get(key, 0))
            last = float(recent[-1].get(key, 0))
            return last - first
        except (ValueError, TypeError):
            return 0

    def summary(self):
        """Generate summary"""
        steps_data = self.steps.get("activities-steps", []) if self.steps else []
        hr_data = self.hr.get("activities-heart", []) if self.hr else []

        avg_steps = self.average_metric(steps_data, "value")

        # Extract resting HR
        resting_hrs = []
        for day in hr_data:
            value = day.get("value", {})
            if isinstance(value, dict):
                resting_hrs.append(value.get("restingHeartRate"))
            else:
                resting_hrs.append(value)

        avg_rhr = sum([r for r in resting_hrs if r]) / len([r for r in resting_hrs if r]) if resting_hrs else None

        return {
            "avg_steps": avg_steps,
            "avg_resting_hr": avg_rhr,
            "steps_trend": self.trend(steps_data, "value"),
            "days_tracked": len(steps_data)
        }


class FitbitReporter:
    """Generate Fitbit reports"""

    def __init__(self, client):
        self.client = client

    def generate_report(self, report_type="weekly", days=None):
        """Generate report"""
        if not days:
            days = 7 if report_type == "weekly" else 30

        end_date = datetime.now().strftime("%Y-%m-%d")
        start_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

        steps = self.client.get_steps(start_date, end_date)
        hr = self.client.get_heartrate(start_date, end_date)
        sleep = self.client.get_sleep(start_date, end_date)

        analyzer = FitbitAnalyzer(steps, hr, sleep)
        summary = analyzer.summary()

        return {
            "report_type": report_type,
            "period": f"{start_date} to {end_date}",
            "summary": summary,
            "data": {
                "steps": steps,
                "heartrate": hr,
                "sleep": sleep
            }
        }


def main():
    parser = argparse.ArgumentParser(description="Fitbit Analytics CLI")
    parser.add_argument("command", choices=["activity", "steps", "calories", "heartrate", "sleep", "report", "summary"],
                       help="Data type to fetch or report type")
    parser.add_argument("--days", type=int, default=7, help="Number of days")
    parser.add_argument("--type", default="weekly", help="Report type")
    parser.add_argument("--client-id", help="Fitbit client ID")
    parser.add_argument("--client-secret", help="Fitbit client secret")
    parser.add_argument("--access-token", help="Fitbit access token")

    args = parser.parse_args()

    try:
        client = FitbitClient(
            client_id=args.client_id,
            client_secret=args.client_secret,
            access_token=args.access_token
        )

        end_date = datetime.now().strftime("%Y-%m-%d")
        start_date = (datetime.now() - timedelta(days=args.days)).strftime("%Y-%m-%d")

        if args.command in ["activity", "steps"]:
            data = client.get_steps(start_date, end_date)
            print(json.dumps(data, indent=2))

        elif args.command == "calories":
            data = client.get_calories(start_date, end_date)
            print(json.dumps(data, indent=2))

        elif args.command == "heartrate":
            data = client.get_heartrate(start_date, end_date)
            print(json.dumps(data, indent=2))

        elif args.command == "sleep":
            data = client.get_sleep(start_date, end_date)
            print(json.dumps(data, indent=2))

        elif args.command == "summary":
            steps = client.get_steps(start_date, end_date)
            hr = client.get_heartrate(start_date, end_date)
            analyzer = FitbitAnalyzer(steps, hr)
            summary = analyzer.summary()
            print(json.dumps(summary, indent=2))

        elif args.command == "report":
            reporter = FitbitReporter(client)
            report = reporter.generate_report(args.type, args.days)
            print(json.dumps(report, indent=2))

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("Set FITBIT_ACCESS_TOKEN or use --access-token", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"API Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
