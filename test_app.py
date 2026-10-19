"""Smoke tests for the secure API (run by the CI `api_test` job and locally).

Uses Flask's test client so no live server is needed.
"""
import os
import tempfile
import unittest

# Use a throwaway SQLite file for the test database.
_TMP = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["DATABASE_URL"] = "sqlite:///" + _TMP.name
os.environ["FLASK_DEBUG"] = "0"

import app as appmod  # noqa: E402


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        self.client = appmod.app.test_client()

    def test_no_token_is_rejected(self):
        r = self.client.get("/api/data")
        self.assertEqual(r.status_code, 401)

    def test_wrong_password_is_rejected(self):
        r = self.client.post("/auth/login",
                             json={"username": "admin", "password": "nope"})
        self.assertEqual(r.status_code, 401)

    def test_missing_body_is_bad_request(self):
        r = self.client.post("/auth/login", json={})
        self.assertEqual(r.status_code, 400)

    def test_valid_login_issues_jwt(self):
        r = self.client.post("/auth/login",
                             json={"username": "admin", "password": "pass1234"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("access_token", r.get_json())

    def test_token_grants_access(self):
        token = self.client.post("/auth/login",
                                 json={"username": "admin", "password": "pass1234"}
                                 ).get_json()["access_token"]
        r = self.client.get("/api/data",
                            headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(r.status_code, 200)

    def test_sql_injection_username_is_ineffective(self):
        payload = "admin' OR '1'='1"
        r = self.client.post("/auth/login",
                             json={"username": payload, "password": "pass1234"})
        # ORM parameterization makes the payload inert -> 401, not a bypass.
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)