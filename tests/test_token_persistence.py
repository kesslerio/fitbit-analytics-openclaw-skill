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

    def write_cache(self, access_token, refresh_token, expires_at):
        self.cache_path.write_text(
            json.dumps(
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_at": expires_at.isoformat(),
                }
            )
        )

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
