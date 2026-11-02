"""Managed Support stable POST guard regression. No Home Assistant, network or MeshCentral calls."""
import importlib.util
import io
import pathlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "smart-pro-managed-support" / "app.py"
spec = importlib.util.spec_from_file_location("managed_support_gate_test_target", SOURCE)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def invoke(path):
    handler = object.__new__(app.Handler)
    handler.path = "/" + path
    form = ("csrf=" + app.CSRF_TOKEN).encode("ascii")
    handler.headers = {"Content-Length": str(len(form))}
    handler.rfile = io.BytesIO(form)
    statuses = []
    handler._send = lambda code, body, content_type: statuses.append(code)
    handler.do_POST()
    return statuses


class StableGateTests(unittest.TestCase):
    def test_expected_version_and_version_independent_gate(self):
        self.assertEqual(app.CONTINUOUS_LIFECYCLE_VERSION, "3.19.3")
        self.assertTrue(app.STABLE_POST_ACTIONS_ONLY)

    def test_legacy_post_routes_are_denied_without_mutation(self):
        forbidden = [
            "pair", "enrollment-check", "settings-check",
            "first-device-execution-canary", "group-migration-preflight",
            "group-migration-target-settings", "group-migration-canary",
            "group-identity-reseed-canary", "candidate-reconnect-canary",
            "candidate-promotion", "runtime-lease-check",
        ]
        with mock.patch.object(app, "read_policy", return_value={}), \
             mock.patch.object(app, "render_page", return_value="safe"), \
             mock.patch.object(app, "pair_with_broker", side_effect=AssertionError("Unexpected pair")):
            for route in forbidden:
                with self.subTest(route=route):
                    self.assertEqual(invoke(route), [409])

    def test_start_stop_remain_explicitly_available(self):
        with mock.patch.object(app, "read_policy", return_value={}), \
             mock.patch.object(app, "render_page", return_value="safe"), \
             mock.patch.object(app, "save_unattended_control") as save, \
             mock.patch.object(app, "start_persistent_runtime") as start, \
             mock.patch.object(app, "stop_persistent_runtime") as stop, \
             mock.patch.object(app, "PERSISTENT_WORKER_ACTIVE", False):
            self.assertEqual(invoke("continuous-runtime-start"), [202])
            self.assertEqual(invoke("continuous-runtime-stop"), [200])
            start.assert_called_once()
            stop.assert_not_called()
            self.assertEqual(save.call_count, 2)

    def test_pairing_ui_is_always_locked_in_stable_source(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("activation_locked = STABLE_POST_ACTIONS_ONLY", source)
        self.assertNotIn("activation_locked = VERSION ==", source)


if __name__ == "__main__":
    unittest.main()
