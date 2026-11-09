"""Managed Support stable POST guard regression. No Home Assistant, network or MeshCentral calls."""
import importlib.util
import io
import pathlib
import subprocess
import sys
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
        self.assertEqual(app.CONTINUOUS_LIFECYCLE_VERSION, "3.19.6")
        self.assertTrue(app.STABLE_POST_ACTIONS_ONLY)

    def test_legacy_post_routes_are_denied_without_mutation(self):
        forbidden = [
            "enrollment-check", "settings-check",
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

    def test_sigterm_exits_cleanly_with_no_managed_identity(self):
        # Real SIGTERM, isolated process and localhost-only HTTP socket.
        script = """
import importlib.util, os, signal, sys, threading
from http.server import ThreadingHTTPServer
spec = importlib.util.spec_from_file_location('managed_signal_test', sys.argv[1])
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
server = ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
timer = threading.Timer(0.25, lambda: os.kill(os.getpid(), signal.SIGTERM))
timer.start()
app._serve_until_shutdown(server)
"""
        result = subprocess.run([sys.executable, "-u", "-c", script, str(SOURCE)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("server closed after requested process shutdown", result.stdout)

    def test_shutdown_prevents_new_managed_runtime(self):
        with mock.patch.object(app, "PROCESS_SHUTDOWN", new=mock.Mock(is_set=lambda: True)):
            with self.assertRaisesRegex(RuntimeError, "managed_shutdown_in_progress"):
                app.start_persistent_runtime()

    def test_stable_gate_does_not_depend_on_version_number(self):
        with mock.patch.object(app, "VERSION", "99.99.99"), \
             mock.patch.object(app, "read_policy", return_value={}), \
             mock.patch.object(app, "render_page", return_value="safe"):
            self.assertEqual(invoke("candidate-promotion"), [409])
            self.assertEqual(invoke("candidate-promotion"), [409])


    def test_customer_pairing_stage_does_not_claim_admin_preapproval(self):
        # Read-only rendering: local policy alone is NOT an Admin preapproval.
        with mock.patch.object(app, "load_identity", return_value=None), \
             mock.patch.object(app, "get_server_state", return_value={}):
            html = app.render_page({
                "allowed_local": True,
                "policy": {"installation_id": "ID-10509"},
            })
        self.assertIn('guide-step ready', html)
        self.assertNotIn('guide-step done', html)
        self.assertIn('δεν επιβεβαιώνει από μόνη της την προέγκριση', html)
        self.assertIn('id="managed_pair_continue"', html)
        self.assertIn('const validCode =', html)
        self.assertIn('next.disabled = !validCode.test', html)

    def test_pairing_ui_respects_assisted_pairing_and_local_gate(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('disabled = "" if local_allowed and ASSISTED_INITIAL_PAIRING_ENABLED else " disabled"', source)
        self.assertIn('if load_identity() is not None:', source)
        self.assertNotIn("activation_locked = VERSION ==", source)


if __name__ == "__main__":
    unittest.main()
