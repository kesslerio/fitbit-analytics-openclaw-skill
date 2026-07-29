import base64
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import fitbit_api


def jwt_with_expiry(expires_at):
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": int(expires_at.timestamp())}).encode()
    ).decode().rstrip("=")
    return f"header.{payload}.signature"


class FitbitTokenPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.secrets_path = root / "secrets.conf"
        self.cache_path = root / "tokens.json"
        self.path_patch = patch.multiple(
            fitbit_api,
            SECRETS_PATH=self.secrets_path,
            TOKEN_CACHE_PATH=self.cache_path,
        )
        self.path_patch.start()
        self.env_patch = patch.dict(os.environ, {}, clear=True)
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()
        self.path_patch.stop()
        self.temp_dir.cleanup()

    def write_secrets(self, access_token, refresh_token):
        self.secrets_path.write_text(
            'FITBIT_CLIENT_ID="client"\n'
            'FITBIT_CLIENT_SECRET="secret"\n'
            f'FITBIT_ACCESS_TOKEN="{access_token}"\n'
            f'FITBIT_REFRESH_TOKEN="{refresh_token}"\n'
        )

    def write_cache(self, access_token, refresh_token, expires_at, client_id="client"):
        payload = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": expires_at.isoformat(),
        }
        if client_id is not None:
            payload["client_id"] = client_id
        self.cache_path.write_text(json.dumps(payload))

    def test_prefers_newer_rotated_cache_pair(self):
        now = datetime.now()
        self.write_secrets(jwt_with_expiry(now + timedelta(hours=1)), "old-refresh")
        self.write_cache(
            jwt_with_expiry(now + timedelta(hours=8)),
            "new-refresh",
            now + timedelta(hours=8),
        )

        client = fitbit_api.FitbitClient()

        self.assertEqual(client._refresh_token, "new-refresh")

    def test_keeps_newer_environment_pair_after_manual_reauth(self):
        now = datetime.now()
        new_access = jwt_with_expiry(now + timedelta(hours=8))
        self.write_secrets(new_access, "new-refresh")
        self.write_cache(
            jwt_with_expiry(now - timedelta(hours=1)),
            "old-refresh",
            now - timedelta(hours=1),
        )

        client = fitbit_api.FitbitClient()

        self.assertEqual(client._access_token, new_access)
        self.assertEqual(client._refresh_token, "new-refresh")

    def test_ignores_cache_written_for_a_different_client(self):
        now = datetime.now()
        env_access = jwt_with_expiry(now + timedelta(hours=1))
        self.write_secrets(env_access, "env-refresh")
        self.write_cache(
            jwt_with_expiry(now + timedelta(hours=8)),
            "other-account-refresh",
            now + timedelta(hours=8),
            client_id="someone-elses-app",
        )

        client = fitbit_api.FitbitClient()

        self.assertEqual(client._access_token, env_access)
        self.assertEqual(client._refresh_token, "env-refresh")

    def test_ignores_legacy_cache_without_client_association(self):
        now = datetime.now()
        env_access = jwt_with_expiry(now + timedelta(hours=1))
        self.write_secrets(env_access, "env-refresh")
        self.write_cache(
            jwt_with_expiry(now + timedelta(hours=8)),
            "unverified-refresh",
            now + timedelta(hours=8),
            client_id=None,
        )

        client = fitbit_api.FitbitClient()

        self.assertEqual(client._refresh_token, "env-refresh")

    def test_save_tokens_stamps_client_association_on_cache(self):
        self.write_secrets("old-access", "old-refresh")
        client = fitbit_api.FitbitClient()

        client._save_tokens("new-access", "new-refresh", 3600)

        cached = json.loads(self.cache_path.read_text())
        self.assertEqual(cached["client_id"], "client")

    def test_jwt_expiry_decodes_base64url_payloads(self):
        exp = datetime.now() + timedelta(hours=4)
        # Find a payload whose base64url encoding uses the url-safe-only
        # characters ('-' or '_'), which standard b64decode rejects.
        for i in range(4096):
            raw = json.dumps({"exp": int(exp.timestamp()), "pad": f"x{i}~\x7f"}).encode()
            encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
            if "-" in encoded or "_" in encoded:
                token = f"header.{encoded}.signature"
                break
        else:
            self.fail("could not construct a url-safe-charset payload")

        decoded = fitbit_api.FitbitClient._jwt_expiry(token)

        self.assertIsNotNone(decoded)
        self.assertEqual(int(decoded.timestamp()), int(exp.timestamp()))

    def test_save_tokens_does_not_treat_leading_digits_as_backreferences(self):
        self.write_secrets("old-access", "old-refresh")
        client = fitbit_api.FitbitClient()

        client._save_tokens("123-access", "456-refresh", 3600)

        content = self.secrets_path.read_text()
        self.assertIn('FITBIT_ACCESS_TOKEN="123-access"', content)
        self.assertIn('FITBIT_REFRESH_TOKEN="456-refresh"', content)
        self.assertEqual(stat.S_IMODE(self.secrets_path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
