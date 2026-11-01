"""Pure policy and real local HTTP tests of Smart Pro read-only preflight."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import threading
import unittest
import urllib.error
import urllib.request

BASE = pathlib.Path(__file__).resolve().parents[1]
APP = BASE / "smart-pro-access-preflight" / "app.py"
sys.path.insert(0, str(APP.parent))
spec = importlib.util.spec_from_file_location("smart_pro_access_preflight_qa", APP)
app = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(app)
USER = "0123456789abcdef0123456789abcdef"


def verify(ip="172.30.32.2", user=USER, groups="system-admin", **extra):
    return app.verify_ingress_admin(ip, {"X-Remote-User-Id": user, "X-Remote-User-Groups": groups, **extra})


class PolicyTests(unittest.TestCase):
    def test_admin_allowed(self):
        self.assertEqual(verify(), {"is_admin": True, "reason": "admin_detected"})

    def test_admin_with_another_group_allowed(self):
        self.assertTrue(verify(groups="system-users,system-admin")["is_admin"])

    def test_user_denied(self):
        self.assertEqual(verify(groups="system-users")["reason"], "non_admin")

    def test_readonly_denied(self):
        self.assertFalse(verify(groups="system-read-only")["is_admin"])

    def test_similar_group_denied(self):
        for group in ("not-system-admin", "system-administrator", "system-admin-extra", "SYSTEM-ADMIN"):
            with self.subTest(group=group):
                self.assertFalse(verify(groups=group)["is_admin"])

    def test_untrusted_ipv4_denied(self):
        for ip in ("127.0.0.1", "192.168.1.20", "172.30.32.3", "172.30.32.21"):
            with self.subTest(ip=ip):
                self.assertEqual(verify(ip=ip)["reason"], "untrusted_source")

    def test_untrusted_ipv6_denied(self):
        self.assertEqual(verify(ip="::1")["reason"], "untrusted_source")

    def test_invalid_ip_denied(self):
        self.assertFalse(verify(ip="not an IP")["is_admin"])

    def test_forwarded_header_no_bypass(self):
        self.assertFalse(verify(ip="127.0.0.1", **{"X-Forwarded-For": "172.30.32.2"})["is_admin"])

    def test_absent_identity_denied(self):
        self.assertEqual(verify(user="")["reason"], "identity_unavailable")

    def test_invalid_identity_denied(self):
        self.assertEqual(verify(user="admin<script>")["reason"], "identity_unavailable")

    def test_empty_groups_denied(self):
        self.assertEqual(verify(groups="")["reason"], "groups_unavailable")

    def test_malformed_groups_denied(self):
        for groups in ("system-admin,", ",system-admin", "system-admin;;users", "system-admin\nhello"):
            with self.subTest(groups=groups):
                self.assertEqual(verify(groups=groups)["reason"], "groups_unavailable")

    def test_oversized_groups_denied(self):
        self.assertEqual(verify(groups="a" * 1025)["reason"], "groups_unavailable")

    def test_too_many_groups_denied(self):
        self.assertEqual(verify(groups=",".join(["system-admin"] + ["x"] * 40))["reason"], "groups_unavailable")

    def test_case_insensitive_header_names(self):
        out = app.verify_ingress_admin("172.30.32.2", {"x-REMOTE-user-ID": USER, "X-Remote-USER-Groups": "system-admin"})
        self.assertTrue(out["is_admin"])

    def test_no_personal_id_in_html(self):
        body = app.render_page(verify()).decode()
        self.assertNotIn(USER, body)
        self.assertNotIn("SUPERVISOR_TOKEN", body)

    def test_no_sensitive_portal_grant_wording(self):
        body = app.render_page(verify()).decode()
        self.assertIn("Το άνοιγμα της σελίδας δεν δημιουργεί λογαριασμό", body)

    def test_admin_only_core_read_permission(self):
        cfg = (BASE / "smart-pro-access-preflight" / "config.yaml").read_text()
        for item in ("hassio_api:", "hassio_role:", "auth_api:", "map:", "ports:"):
            self.assertNotIn(item, cfg)
        self.assertIn("homeassistant_api: true", cfg)
        self.assertIn("host_network: false", cfg)
        self.assertIn("panel_admin: false", cfg)
        self.assertIn("init: true", cfg)

    def test_privileged_commands_isolated_in_lab_module(self):
        source = APP.read_text()
        self.assertNotIn("config/auth/create", source)
        self.assertNotIn("config/auth_provider/homeassistant/create", source)
        writer=(BASE/"smart-pro-access-preflight"/"account_roundtrip.py").read_text()
        self.assertIn("config/auth/create", writer)
        self.assertNotIn("config/auth_provider/homeassistant/create", writer)


class RealLocalHttpTests(unittest.TestCase):
    """Real socket HTTP tests: localhost must always be rejected, even with forged headers."""

    @classmethod
    def setUpClass(cls):
        cls.server = app.Server(("127.0.0.1", 0), app.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def request(self, path, method="GET"):
        req = urllib.request.Request(self.url + path, method=method, headers={
            "X-Remote-User-Id": USER,
            "X-Remote-User-Groups": "system-admin",
            "X-Forwarded-For": "172.30.32.2",
        })
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers

    def test_http_forged_admin_denied(self):
        status, body, headers = self.request("/")
        self.assertEqual(status, 403)
        self.assertIn("Δεν επιβεβαιώθηκε διαχειριστής".encode(), body)
        self.assertEqual(headers.get("Cache-Control"), "no-store, private, max-age=0")

    def test_http_json_returns_boolean_only(self):
        status, body, _ = self.request("/status?ignored=true")
        self.assertEqual(status, 403)
        obj = json.loads(body)
        self.assertEqual(obj, {"version": "0.5.0", "is_admin": False, "reason": "untrusted_source"})
        self.assertNotIn(USER.encode(), body)

    def test_http_post_denied(self):
        status, body, _ = self.request("/", method="POST")
        self.assertEqual(status, 405)
        self.assertEqual(body, b"Unsupported action")

    def test_http_unknown_route_404(self):
        status, _, _ = self.request("/admin/create-user")
        self.assertEqual(status, 404)

    def test_http_delete_denied(self):
        status, _, _ = self.request("/", method="DELETE")
        self.assertEqual(status, 405)


if __name__ == "__main__":
    unittest.main()
