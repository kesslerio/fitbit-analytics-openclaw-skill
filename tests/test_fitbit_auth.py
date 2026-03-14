import io
import json
import sys
import tempfile
import threading
import time as pytime
import unittest
import urllib.error
import urllib.parse
from contextlib import redirect_stderr
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import fitbit_api
import refresh_tokens


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class FitbitAuthTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.tempdir.name)
        self.secrets_path = self.temp_path / "secrets.conf"
        self.cache_path = self.temp_path / "tokens.json"
        self.lock_path = self.temp_path / "tokens.lock"
        self.secrets_path.write_text(
            'FITBIT_ACCESS_TOKEN="old_access"\nFITBIT_REFRESH_TOKEN="old_refresh"\n',
            encoding="utf-8",
        )

        self.patches = [
            mock.patch.object(fitbit_api, "SECRETS_PATH", self.secrets_path),
            mock.patch.object(fitbit_api, "TOKEN_CACHE_PATH", self.cache_path),
            mock.patch.object(fitbit_api, "TOKEN_LOCK_PATH", self.lock_path),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        self.tempdir.cleanup()

    def make_client(self):
        return fitbit_api.FitbitClient(client_id="client", client_secret="secret")

    def http_error(self, code, reason, payload=None):
        body = b""
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
        return urllib.error.HTTPError(
            url="https://api.fitbit.com/oauth2/token",
            code=code,
            msg=reason,
            hdrs=None,
            fp=io.BytesIO(body),
        )

    def test_save_tokens_persists_digit_prefixed_values(self):
        client = self.make_client()

        client._save_tokens("123access", "456refresh", 3600)

        secrets_content = self.secrets_path.read_text(encoding="utf-8")
        self.assertIn('FITBIT_ACCESS_TOKEN="123access"', secrets_content)
        self.assertIn('FITBIT_REFRESH_TOKEN="456refresh"', secrets_content)

        cache_data = json.loads(self.cache_path.read_text(encoding="utf-8"))
        self.assertEqual(cache_data["access_token"], "123access")
        self.assertEqual(cache_data["refresh_token"], "456refresh")
        self.assertIn("refreshed_at", cache_data)

    def test_client_prefers_secrets_file_tokens_over_stale_cache(self):
        self.cache_path.write_text(
            json.dumps(
                {
                    "access_token": "stale_cache_access",
                    "refresh_token": "stale_cache_refresh",
                    "expires_at": (datetime.now() + timedelta(hours=1)).isoformat(),
                    "refreshed_at": datetime.now().isoformat(),
                }
            ),
            encoding="utf-8",
        )

        client = self.make_client()

        self.assertEqual(client._access_token, "old_access")
        self.assertEqual(client._refresh_token, "old_refresh")

    def test_request_refreshes_before_api_call_when_token_is_near_expiry(self):
        client = self.make_client()
        client._token_expires_at = datetime.now() + timedelta(minutes=30)
        events = []

        def fake_refresh(*args, **kwargs):
            events.append("refresh")
            return True

        def fake_urlopen(req, timeout=10):
            events.append("request")
            return FakeResponse({"ok": True})

        with mock.patch.object(client, "refresh_access_token", side_effect=fake_refresh) as refresh_mock:
            with mock.patch.object(fitbit_api.urllib.request, "urlopen", side_effect=fake_urlopen):
                response = client._request("1/user/-/profile.json")

        self.assertEqual(response, {"ok": True})
        self.assertEqual(events, ["refresh", "request"])
        refresh_mock.assert_called_once_with()

    def test_request_skips_preflight_refresh_when_refresh_credentials_are_missing(self):
        client = fitbit_api.FitbitClient(access_token="token_only_access")
        client._token_expires_at = None

        with mock.patch.object(client, "refresh_access_token") as refresh_mock:
            with mock.patch.object(
                fitbit_api.urllib.request,
                "urlopen",
                return_value=FakeResponse({"ok": True}),
            ):
                response = client._request("1/user/-/profile.json")

        self.assertEqual(response, {"ok": True})
        refresh_mock.assert_not_called()

    def test_request_continues_when_preflight_refresh_fails(self):
        client = self.make_client()
        client._token_expires_at = datetime.now() + timedelta(minutes=30)

        with mock.patch.object(
            client,
            "refresh_access_token",
            side_effect=fitbit_api.FitbitAuthError("temporary refresh failure"),
        ) as refresh_mock:
            with mock.patch.object(
                fitbit_api.urllib.request,
                "urlopen",
                return_value=FakeResponse({"ok": True}),
            ):
                response = client._request("1/user/-/profile.json")

        self.assertEqual(response, {"ok": True})
        refresh_mock.assert_called_once_with()

    def test_request_retries_once_on_401_with_stale_metadata(self):
        client = self.make_client()
        client._token_expires_at = datetime.now() + timedelta(hours=4)

        responses = [
            self.http_error(401, "Unauthorized"),
            FakeResponse({"ok": True}),
        ]

        def fake_urlopen(req, timeout=10):
            next_item = responses.pop(0)
            if isinstance(next_item, Exception):
                raise next_item
            return next_item

        with mock.patch.object(client, "refresh_access_token", return_value=True) as refresh_mock:
            with mock.patch.object(fitbit_api.urllib.request, "urlopen", side_effect=fake_urlopen):
                response = client._request("1/user/-/activities/date/2026-03-14.json")

        self.assertEqual(response, {"ok": True})
        refresh_mock.assert_called_once_with(force=True)

    def test_refresh_access_token_raises_reauth_error_for_invalid_grant(self):
        client = self.make_client()
        client._save_tokens("old_access", "old_refresh", 3600)
        before_secrets = self.secrets_path.read_text(encoding="utf-8")
        before_cache = self.cache_path.read_text(encoding="utf-8")

        error = self.http_error(
            400,
            "Bad Request",
            {"errors": [{"errorType": "invalid_grant", "message": "Refresh token invalid"}]},
        )

        with mock.patch.object(fitbit_api.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(fitbit_api.FitbitReauthRequiredError):
                client.refresh_access_token(force=True)

        self.assertEqual(self.secrets_path.read_text(encoding="utf-8"), before_secrets)
        self.assertEqual(self.cache_path.read_text(encoding="utf-8"), before_cache)

    def test_refresh_access_token_retries_transient_network_errors_without_mutating_tokens(self):
        client = self.make_client()
        client._save_tokens("old_access", "old_refresh", 3600)
        before_secrets = self.secrets_path.read_text(encoding="utf-8")
        before_cache = self.cache_path.read_text(encoding="utf-8")

        with mock.patch.object(
            fitbit_api.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("network down"),
        ) as urlopen_mock:
            with mock.patch.object(fitbit_api.time, "sleep") as sleep_mock:
                with self.assertRaises(fitbit_api.FitbitAuthError):
                    client.refresh_access_token(force=True)

        self.assertEqual(urlopen_mock.call_count, len(client.REFRESH_RETRY_DELAYS_SECONDS))
        self.assertEqual(sleep_mock.call_count, len(client.REFRESH_RETRY_DELAYS_SECONDS) - 1)
        self.assertEqual(self.secrets_path.read_text(encoding="utf-8"), before_secrets)
        self.assertEqual(self.cache_path.read_text(encoding="utf-8"), before_cache)

    def test_refresh_access_token_uses_explicit_refresh_token_instead_of_cache(self):
        self.cache_path.write_text(
            json.dumps(
                {
                    "access_token": "cache_access",
                    "refresh_token": "cache_refresh",
                    "expires_at": (datetime.now() + timedelta(hours=1)).isoformat(),
                    "refreshed_at": datetime.now().isoformat(),
                }
            ),
            encoding="utf-8",
        )
        client = fitbit_api.FitbitClient(
            client_id="client",
            client_secret="secret",
            access_token="explicit_access",
            refresh_token="explicit_refresh",
        )

        def fake_urlopen(req, timeout=10):
            request_payload = urllib.parse.parse_qs(req.data.decode("utf-8"))
            self.assertEqual(request_payload["refresh_token"], ["explicit_refresh"])
            return FakeResponse(
                {
                    "access_token": "rotated_access",
                    "refresh_token": "rotated_refresh",
                    "expires_in": 3600,
                }
            )

        with mock.patch.object(fitbit_api.urllib.request, "urlopen", side_effect=fake_urlopen):
            refreshed = client.refresh_access_token(force=True)

        self.assertTrue(refreshed)
        self.assertEqual(client._access_token, "rotated_access")
        self.assertEqual(client._refresh_token, "rotated_refresh")

    def test_refresh_access_token_waits_for_lock_before_refreshing(self):
        client = self.make_client()
        release_lock = threading.Event()
        refresh_finished = threading.Event()

        def hold_lock():
            with client._token_lock():
                release_lock.wait(timeout=2)

        holder = threading.Thread(target=hold_lock)
        holder.start()
        pytime.sleep(0.1)

        def refresh_in_thread():
            try:
                client.refresh_access_token(force=True)
            finally:
                refresh_finished.set()

        refresher = threading.Thread(target=refresh_in_thread)
        with mock.patch.object(
            fitbit_api.urllib.request,
            "urlopen",
            return_value=FakeResponse(
                {
                    "access_token": "new_access",
                    "refresh_token": "new_refresh",
                    "expires_in": 3600,
                }
            ),
        ):
            refresher.start()
            pytime.sleep(0.1)
            self.assertFalse(refresh_finished.is_set())
            release_lock.set()
            refresher.join(timeout=2)

        holder.join(timeout=2)
        self.assertTrue(refresh_finished.is_set())

    def test_refresh_cli_skips_when_tokens_are_current(self):
        fake_client = mock.Mock()
        fake_client.refresh_access_token.return_value = False

        stderr = io.StringIO()
        with mock.patch.object(refresh_tokens, "FitbitClient", return_value=fake_client):
            with redirect_stderr(stderr):
                exit_code = refresh_tokens.main([])

        self.assertEqual(exit_code, 0)
        fake_client.refresh_access_token.assert_called_once_with(force=False, max_age_hours=6)
        self.assertIn("refresh skipped", stderr.getvalue())

    def test_refresh_cli_refreshes_when_due(self):
        fake_client = mock.Mock()
        fake_client.refresh_access_token.return_value = True

        stderr = io.StringIO()
        with mock.patch.object(refresh_tokens, "FitbitClient", return_value=fake_client):
            with redirect_stderr(stderr):
                exit_code = refresh_tokens.main(["--max-age-hours", "8"])

        self.assertEqual(exit_code, 0)
        fake_client.refresh_access_token.assert_called_once_with(force=False, max_age_hours=8)
        self.assertIn("tokens refreshed", stderr.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
