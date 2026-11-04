"""Offline first-seed pilot regression; no network, WordPress or Docker changes."""
import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock
from contextlib import ExitStack

SRC = pathlib.Path(__file__).resolve().parents[1] / 'smart-pro-managed-support' / 'app.py'
spec = importlib.util.spec_from_file_location('direct_pilot_app', SRC)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
NODE = 'SPMN-' + 'C' * 32
IDENT = {'installation_id': 'ID-86995', 'node_id': NODE, 'node_secret': 'fake-example'}
POLICY = {'allowed_local': True, 'policy': {'installation_id': 'ID-86995'}}
SERVER = {'authorized_server': True, 'installation_id': 'ID-86995', 'node_id': NODE, 'valid_until': 9999999999}

class DirectPilot(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        patch = self.stack.enter_context
        patch(mock.patch.object(app, 'ARCH', 'amd64'))
        patch(mock.patch.object(app, 'load_identity', return_value=IDENT))
        patch(mock.patch.object(app, 'read_policy', return_value=POLICY))
        patch(mock.patch.object(app, 'get_server_state', return_value=SERVER))
        patch(mock.patch.object(app, 'get_mesh_identity_status', return_value={'state':'not_seeded'}))
        patch(mock.patch.object(app, 'load_unattended_control', return_value={'enabled':False}))
        patch(mock.patch.object(app, 'PROCESS_SHUTDOWN', new=mock.Mock(is_set=lambda:False)))
        for name in ('CANARY_WORKER_ACTIVE', 'PERSISTENT_WORKER_ACTIVE', 'FIRST_DEVICE_EXECUTION_WORKER_ACTIVE',
                     'MIGRATION_CANARY_WORKER_ACTIVE', 'IDENTITY_RESEED_WORKER_ACTIVE',
                     'CANDIDATE_RECONNECT_WORKER_ACTIVE', 'PROMOTION_WORKER_ACTIVE'):
            patch(mock.patch.object(app, name, False))
        temp = patch(tempfile.TemporaryDirectory())
        self.base = pathlib.Path(temp)
        patch(mock.patch.object(app, 'DATA_DIR', self.base))
        patch(mock.patch.object(app, 'FIRST_SEED_ATTEMPT_FILE', self.base / 'one-shot.json'))
        patch(mock.patch.object(app, 'CANARY_STATE_FILE', self.base / 'canary.json'))
    def tearDown(self):self.stack.close()

    def test_id86995_is_only_new_scope_and_ready(self):
        self.assertTrue(app.first_seed_pilot_readiness()[0])
        for wrong in ('ID-12345','ID-34973','ID-95948'):
            with self.subTest(wrong=wrong), mock.patch.object(app,'load_identity',return_value={**IDENT,'installation_id':wrong}):
                self.assertFalse(app.first_seed_pilot_readiness()[0])
    def test_unauthorized_and_wrong_arch_blocked(self):
        with mock.patch.object(app,'get_server_state',return_value={**SERVER,'authorized_server':False}):
            self.assertFalse(app.first_seed_pilot_readiness()[0])
        with mock.patch.object(app,'ARCH','aarch64'):
            self.assertFalse(app.first_seed_pilot_readiness()[0])
        with mock.patch.object(app,'read_policy',return_value={'allowed_local':True,'policy':{'installation_id':'ID-28422'}}):
            self.assertFalse(app.first_seed_pilot_readiness()[0])
    def test_one_shot_latch_denies_second_attempt(self):
        with mock.patch.object(app,'start_connectivity_canary') as start, mock.patch.object(app,'_execution_settings_material',return_value={'runtime_source':'target','target_group_name':'Smart Pro Managed — ID-86995','raw':b'none'}):
            app.request_first_seed_pilot()
            start.assert_called_once()
            self.assertFalse(app.first_seed_pilot_readiness()[0])
            with self.assertRaises(RuntimeError): app.request_first_seed_pilot()
    def test_first_seed_target_name_exact(self):
        # A new direct pilot must refuse a server response with a shared MeshCentral group.
        raw = {'MeshName':'Smart Pro Managed — ID-86995','MeshType':'2','MeshID':'example-mesh-id',
               'ServerID':'example-server','MeshServer':'wss://support.smart-pro-system.com/agent.ashx','agentName':'SPMNG-'+'A'*16}
        self.assertEqual(raw['MeshName'], f'Smart Pro Managed — {app.DIRECT_SEED_PILOT_INSTALLATION}')
        invalid={**raw,'MeshName':'Smart Pro Managed Support'}
        self.assertNotEqual(invalid['MeshName'], f'Smart Pro Managed — {app.DIRECT_SEED_PILOT_INSTALLATION}')
        self.assertIn("if _safe_str(fields.get('MeshName'), 200) != expected_group:",SRC.read_text())
    def test_wrong_source_preflight_must_not_consume_attempt(self):
        with mock.patch.object(app,'_execution_settings_material',return_value={
                'runtime_source':'shared','target_group_name':'Smart Pro Managed Support','raw':b'dummy'}):
            with self.assertRaisesRegex(RuntimeError,'direct_seed_preflight_denied'):
                app.request_first_seed_pilot()
            self.assertFalse(app.FIRST_SEED_ATTEMPT_FILE.exists())
    def test_target_source_preflight_runs_before_canary(self):
        probe={'runtime_source':'target','target_group_name':'Smart Pro Managed — ID-86995','raw':b'dummy'}
        with mock.patch.object(app,'_execution_settings_material',return_value=probe) as src, \
             mock.patch.object(app,'start_connectivity_canary') as canary:
            app.request_first_seed_pilot()
            src.assert_called_once()
            canary.assert_called_once()
            self.assertTrue(app.FIRST_SEED_ATTEMPT_FILE.exists())
            self.assertEqual(probe['raw'], b'')
    def test_target_runtime_reuse_path(self):
        target={'raw':b'dummy','fields':{'MeshName':'Smart Pro Managed — ID-86995'},'agent_label':'SPMNG-'+'A'*16,
                'runtime_source':'target'}
        with mock.patch.object(app,'_execution_settings_material',return_value=target) as get:
            self.assertEqual(app._persistent_settings_material(IDENT,{'runtime_source':'target'})['runtime_source'],'target')
            get.assert_called_once_with(IDENT)
        with self.assertRaisesRegex(RuntimeError,'direct_seed_source_not_target'):
            app._persistent_settings_material(IDENT, {'runtime_source':'shared'})
    def test_fails_if_source_missing_target_flag(self):
        with mock.patch.object(app,'_execution_settings_material',return_value={'runtime_source':'shared'}):
            with self.assertRaisesRegex(RuntimeError,'direct_seed_settings_mismatch'):
                app._persistent_settings_material(IDENT, {'runtime_source':'target'})

if __name__=='__main__': unittest.main()
