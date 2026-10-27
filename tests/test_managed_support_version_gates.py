"""Offline policy tests: execute only AST-selected handler code with inert stubs.

No app import, server, real POST, thread, state write, Broker or MeshAgent call.
Run with Python -B; --source selects an original or proposed app.py.
"""
import argparse
import ast
import copy
import io
from pathlib import Path
import re
import secrets
import sys
from types import SimpleNamespace
import unittest
from urllib.parse import parse_qs, urlparse

parser = argparse.ArgumentParser()
parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1] / 'smart-pro-managed-support/app.py')
args, unittest_args = parser.parse_known_args()
SOURCE = args.source.read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)


def prohibit_external_effects(event, details):
    if event.startswith('socket.') or event in {'subprocess.Popen', 'os.system', 'os.fork', 'os.posix_spawn'}:
        raise AssertionError('External operation forbidden in isolated gate test: ' + event)


sys.addaudithook(prohibit_external_effects)
HANDLER = next(n for n in TREE.body if isinstance(n, ast.ClassDef) and n.name == 'Handler')
POST = next(n for n in HANDLER.body if isinstance(n, ast.FunctionDef) and n.name == 'do_POST')
ARCHIVED = {
    'pair': 'pair_with_broker',
    'enrollment-check': 'verify_enrollment_authorization',
    'settings-check': 'verify_secure_settings',
    'first-device-settings-check': 'verify_first_device_settings_delivery',
    'first-device-execution-canary': 'start_first_device_execution_canary',
    'first-device-retry-reset-consume': 'consume_first_device_retry_reset',
    'agent-check': 'verify_agent_binary',
    'runtime-lease-check': 'start_runtime_lease_dry_run',
    'identity-continuity-canary': 'start_connectivity_canary',
    'group-migration-preflight': 'verify_group_migration_preflight',
    'group-migration-target-settings': 'verify_group_migration_target_settings',
    'group-migration-canary': 'start_group_migration_canary',
    'group-identity-reseed-canary': 'start_group_identity_reseed_canary',
    'candidate-reconnect-canary': 'start_candidate_reconnect_canary',
    'candidate-promotion': 'start_candidate_promotion',
}
CONTROLS = {'continuous-runtime-start': 'start_persistent_runtime', 'continuous-runtime-stop': 'stop_persistent_runtime'}
VERSIONS = ('3.19.1', '3.19.2')


class DispatchReached(BaseException):
    """Stop immediately at an inert action stub, before any real action body."""


def constants():
    result = {}
    for n in TREE.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            name = n.targets[0].id
            if name.startswith('CONTINUOUS_LIFECYCLE_VERSION') or name in {'FIRST_DEVICE_EXECUTION_VERSION', 'MAX_POST_BYTES'}:
                result[name] = ast.literal_eval(n.value)
    return result


def simulate(version, route, *, active=False, csrf='offline-test-csrf', length=None, arch='amd64'):
    calls = []
    ns = constants()
    ns.update(VERSION=version, ARCH=arch, PERSISTENT_WORKER_ACTIVE=active,
              CSRF_TOKEN='offline-test-csrf', parse_qs=parse_qs, urlparse=urlparse,
              secrets=secrets, read_policy=lambda: {}, load_identity=lambda: None,
              render_page=lambda *a, **k: 'inert test page')

    def stub(name):
        def stopped(*a, **k):
            calls.append((name, a))
            raise DispatchReached()
        return stopped

    for name in set(ARCHIVED.values()) | set(CONTROLS.values()):
        ns[name] = stub(name)
    ns['save_unattended_control'] = lambda *a: calls.append(('save_unattended_control', a))
    selected = [copy.deepcopy(n) for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name in {'_as_int', '_safe_str'}]
    selected.append(copy.deepcopy(POST))
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(args.source), 'exec'), ns)
    body = ('csrf=' + csrf).encode()
    responses = []
    fake = SimpleNamespace(path=route, headers={'Content-Length': str(len(body) if length is None else length)},
                           rfile=io.BytesIO(body), _send=lambda code, *a: responses.append(code))
    try:
        ns['do_POST'](fake)
    except DispatchReached:
        return 'dispatch', calls
    return responses[-1] if responses else None, calls


class VersionGateTests(unittest.TestCase):
    def test_all_recognized_routes_have_test_cases(self):
        routes = set()
        for n in ast.walk(POST):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == 'endswith':
                routes.add(ast.literal_eval(n.args[0]).lstrip('/'))
        self.assertEqual(routes, set(ARCHIVED) | set(CONTROLS))

    def test_all_archived_actions_denied_before_any_dispatch_or_state_write(self):
        for version in VERSIONS:
            for arch in ('amd64', 'aarch64'):
                for active in (False, True):
                    for route in ARCHIVED:
                        with self.subTest(version=version, arch=arch, active=active, route=route):
                            result, calls = simulate(version, '/' + route, active=active, arch=arch)
                            self.assertEqual((result, calls), (409, []))

    def test_ingress_prefix_query_and_trailing_slash_do_not_bypass_archive(self):
        for version in VERSIONS:
            for route in ARCHIVED:
                with self.subTest(version=version, route=route):
                    self.assertEqual(simulate(version, '/api/hassio_ingress/offline/' + route + '/?x=1'), (409, []))

    def test_start_stop_dispatch_and_existing_worker_guard_preserved(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                self.assertEqual(simulate(version, '/continuous-runtime-start'),
                                 ('dispatch', [('save_unattended_control', (True, 'admin_enabled')), ('start_persistent_runtime', ())]))
                self.assertEqual(simulate(version, '/continuous-runtime-start', active=True), (409, []))
                self.assertEqual(simulate(version, '/continuous-runtime-stop', active=True),
                                 ('dispatch', [('save_unattended_control', (False, 'admin_paused')), ('stop_persistent_runtime', ())]))
                self.assertEqual(simulate(version, '/continuous-runtime-stop'),
                                 (200, [('save_unattended_control', (False, 'admin_paused'))]))

    def test_invalid_csrf_denied_before_action_dispatch(self):
        for version in VERSIONS:
            for route in set(ARCHIVED) | set(CONTROLS):
                with self.subTest(version=version, route=route):
                    self.assertEqual(simulate(version, '/' + route, csrf='invalid'), (403, []))

    def test_body_length_limits_preserved(self):
        for version in VERSIONS:
            for length in (0, -1, constants()['MAX_POST_BYTES'] + 1, 'invalid'):
                with self.subTest(version=version, length=length):
                    self.assertEqual(simulate(version, '/continuous-runtime-start', length=length), (400, []))

    def test_unknown_action_is_404(self):
        for version in VERSIONS:
            self.assertEqual(simulate(version, '/not-an-action'), (404, []))

    def test_first_device_checkpoint_keeps_its_existing_dispatch_boundary(self):
        allowed = {'first-device-execution-canary', 'first-device-retry-reset-consume'}
        for route, function in {**ARCHIVED, **CONTROLS}.items():
            with self.subTest(route=route):
                expected = ('dispatch', [(function, ())]) if route in allowed else (409, [])
                self.assertEqual(simulate('3.17.4', '/' + route), expected)
        # The historical 3.16.0 settings checkpoint is not generalized or blocked.
        self.assertEqual(simulate('3.16.0', '/first-device-settings-check'),
                         ('dispatch', [('verify_first_device_settings_delivery', ())]))

    def test_all_three_shared_gate_sites_cover_both_stable_versions(self):
        # Extract the real UI assignment, POST restriction and startup log condition.
        expressions = []
        for n in ast.walk(TREE):
            if isinstance(n, ast.Compare) and any(isinstance(x, ast.Name) and x.id.startswith('CONTINUOUS_LIFECYCLE_VERSION') for x in ast.walk(n)):
                expressions.append(n)
        self.assertEqual(len(expressions), 3)
        for version in VERSIONS:
            for expression in expressions:
                with self.subTest(version=version, line=expression.lineno):
                    self.assertTrue(eval(compile(ast.Expression(copy.deepcopy(expression)), '<isolated gate expression>', 'eval'),
                                         dict(constants(), VERSION=version)))

    def test_current_config_version_keeps_archive_closed(self):
        config = args.source.with_name('config.yaml').read_text()
        version = re.search(r'^version:\s*"([^"]+)"', config, re.M).group(1)
        for route in ARCHIVED:
            with self.subTest(version=version, route=route):
                self.assertEqual(simulate(version, '/' + route), (409, []))


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *unittest_args])
