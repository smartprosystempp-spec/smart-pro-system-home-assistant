"""Isolated tests: exactly matching current HA admin via fresh Core readback."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
ADDON = ROOT / "smart-pro-access-preflight"
sys.path.insert(0, str(ADDON))
spec = importlib.util.spec_from_file_location("qa_access_v02", ADDON / "app.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
from ha_readback import AdminReadbackError

U = "0123456789abcdef0123456789abcdef"
TOKEN = "TEST_ONLY_NOT_REAL_TOKEN__1234567890"


def headers(groups="system-admin", user=U):
    return {"X-Remote-User-Id": user, "X-Remote-User-Groups": groups}


def rec(**changes):
    u = {"id": U, "is_active": True, "is_owner": False, "system_generated": False,
         "group_ids": ["system-admin"]}
    u.update(changes)
    return u


class RoleReadbackTests(unittest.TestCase):
    def call(self, *, peer="172.30.32.2", headers_override=None, records=None,
             exc=None, token_supplier=None):
        counts = {"tokens": 0, "reads": 0}
        def token():
            counts["tokens"] += 1
            return TOKEN
        def reader(*, supervisor_token):
            counts["reads"] += 1
            self.assertEqual(supervisor_token, TOKEN)
            if exc: raise exc
            return [rec()] if records is None else records
        result = app.verify_live_core_admin(
            peer, headers() if headers_override is None else headers_override,
            token_supplier=token if token_supplier is None else token_supplier,
            user_reader=reader)
        return result, counts

    def assert_blocked(self, reason, **kw):
        outcome, counts = self.call(**kw)
        self.assertEqual(outcome, {"is_admin": False, "reason": reason})
        return counts

    def test_admin_with_exact_matching_core_user(self):
        result, counts = self.call()
        self.assertEqual(result, {"is_admin": True, "reason": "admin_and_core_verified_read_only"})
        self.assertEqual(counts, {"tokens": 1, "reads": 1})

    def test_owner_matching_core_user(self):
        result,_ = self.call(records=[rec(is_owner=True, group_ids=[])])
        self.assertTrue(result["is_admin"])

    def test_nonadmin_denied_before_token_read(self):
        counts = self.assert_blocked("non_admin", headers_override=headers(groups="system-users"))
        self.assertEqual(counts, {"tokens": 0, "reads": 0})

    def test_direct_request_denied_before_token_read(self):
        counts = self.assert_blocked("untrusted_source", peer="127.0.0.1")
        self.assertEqual(counts, {"tokens": 0, "reads": 0})

    def test_wrong_user_id_denied(self):
        self.assert_blocked("core_identity_not_matched", records=[rec(id="a" * 32)])

    def test_readonly_core_user_denied(self):
        self.assert_blocked("core_user_not_admin", records=[rec(group_ids=["system-users"])])

    def test_inactive_admin_denied(self):
        self.assert_blocked("core_user_not_admin", records=[rec(is_active=False)])

    def test_system_generated_admin_denied(self):
        self.assert_blocked("core_user_not_admin", records=[rec(system_generated=True)])

    def test_duplicate_user_id_denied(self):
        self.assert_blocked("core_identity_not_matched", records=[rec(), rec()])

    def test_missing_core_token_denied(self):
        self.assert_blocked("core_authority_denied", exc=AdminReadbackError("local_ha_token_unavailable"))

    def test_ha_api_command_denied(self):
        self.assert_blocked("core_authority_denied", exc=AdminReadbackError("ha_user_list_denied"))

    def test_transport_connection_fails_closed(self):
        self.assert_blocked("core_readback_failed", exc=AdminReadbackError("ha_connection_failed"))

    def test_no_user_list(self):
        self.assert_blocked("core_identity_not_matched", records=[])

    def test_unexpected_exception_no_leak(self):
        self.assert_blocked("core_readback_failed", exc=ValueError("SECRET-DO-NOT-LEAK"))

    def test_role_readback_is_not_consent(self):
        result,_=self.call()
        self.assertNotIn("consent", result)
        self.assertNotIn("credential", result)
        self.assertNotIn("user_id", result)
        self.assertNotIn(U, str(result))

    def test_correct_lowercase_headers(self):
        result,_=self.call(headers_override={"x-remote-user-id":U,"x-remote-user-groups":"system-admin"})
        self.assertTrue(result["is_admin"])

    def test_ambiguous_identity_header_is_denied(self):
        self.assert_blocked("identity_unavailable", headers_override={
            "X-Remote-User-Id": U, "x-remote-user-id": "b"*32, "X-Remote-User-Groups":"system-admin"})

    def test_no_create_user_code_in_addon(self):
        for name in ("app.py", "ha_readback.py"):
            data=(ADDON/name).read_text()
            for forbidden in ("config/auth/create", "config/auth/delete", "config/auth_provider/homeassistant/create"):
                self.assertNotIn(forbidden, data)

    def test_version_tag_consistent(self):
        self.assertEqual(app.APP_VERSION,"0.5.0")
        self.assertIn('version: "0.5.0"',(ADDON/'config.yaml').read_text())
        self.assertIn('BUILD_VERSION=0.5.0',(ADDON/'Dockerfile').read_text())

if __name__ == "__main__":
    unittest.main()
