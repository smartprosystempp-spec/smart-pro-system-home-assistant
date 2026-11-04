"""Pure offline first-seed contract checks for the target-only assisted v3.19.7 path."""
import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / 'smart-pro-managed-support' / 'app.py'
spec = importlib.util.spec_from_file_location('managed_assisted_3197', SRC)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
app.VERSION = '3.19.7'  # version-pinned regression of historic one-shot first-seed gate

NODE = 'SPMN-' + 'A' * 32
ID = {'installation_id': 'ID-56674', 'node_id': NODE, 'node_secret': 'fake'}

class AssistedFirstSeedTests(unittest.TestCase):
    def test_new_id_is_scoped_but_legacy_is_not(self):
        self.assertTrue(app.assisted_first_seed_scope(ID))
        self.assertFalse(app.assisted_first_seed_scope({**ID, 'installation_id': 'ID-86995'}))
        self.assertFalse(app.assisted_first_seed_scope({**ID, 'installation_id': 'ID-28422'}))
        self.assertFalse(app.assisted_first_seed_scope({**ID, 'installation_id': 'ID-999'}))
        with mock.patch.object(app, 'VERSION', '3.19.6'):
            self.assertFalse(app.assisted_first_seed_scope(ID))

    def test_first_seed_ready_for_exact_active_authorized_new_identity(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(app, 'load_identity', return_value=ID), \
             mock.patch.object(app, 'read_policy', return_value={'allowed_local': True,'policy': {'installation_id':'ID-56674'}}), \
             mock.patch.object(app, 'get_server_state', return_value={
                 'authorized_server':True,'valid_until':app.now_ts()+300,
                 'installation_id':'ID-56674','node_id':NODE}), \
             mock.patch.object(app,'get_mesh_identity_status',return_value={'state':'not_seeded'}), \
             mock.patch.object(app,'FIRST_SEED_ATTEMPT_FILE',pathlib.Path(d)/'attempt'), \
             mock.patch.object(app,'CANARY_STATE_FILE',pathlib.Path(d)/'report'), \
             mock.patch.object(app,'load_unattended_control',return_value={'enabled':False}), \
             mock.patch.object(app,'ARCH','amd64'), \
             mock.patch.object(app,'CANARY_WORKER_ACTIVE',False), \
             mock.patch.object(app,'PERSISTENT_WORKER_ACTIVE',False):
            self.assertTrue(app.first_seed_pilot_readiness()[0])
            (pathlib.Path(d)/'attempt').write_text('old-attempt')
            self.assertFalse(app.first_seed_pilot_readiness()[0])

    def test_unauthorized_trial_denies_without_latch(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(app,'load_identity',return_value=ID), \
             mock.patch.object(app,'read_policy',return_value={'allowed_local':False,'policy': {'installation_id':'ID-56674'}}), \
             mock.patch.object(app,'FIRST_SEED_ATTEMPT_FILE',pathlib.Path(d)/'attempt'), \
             mock.patch.object(app,'CANARY_STATE_FILE',pathlib.Path(d)/'report'):
            self.assertFalse(app.first_seed_pilot_readiness()[0]);self.assertFalse((pathlib.Path(d)/'attempt').exists())

    def test_target_only_preflight_before_any_latch(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(app,'first_seed_pilot_readiness',return_value=(True,'ok')), \
             mock.patch.object(app,'load_identity',return_value=ID), \
             mock.patch.object(app,'DATA_DIR',pathlib.Path(d)), \
             mock.patch.object(app,'FIRST_SEED_ATTEMPT_FILE',pathlib.Path(d)/'attempt'), \
             mock.patch.object(app,'start_connectivity_canary') as start:
            with mock.patch.object(app,'_execution_settings_material',return_value={
                     'raw':b'mock','runtime_source':'shared','target_group_name':'Smart Pro Managed Support'}):
                with self.assertRaisesRegex(RuntimeError,'assisted_seed_preflight_denied'):
                    app.request_first_seed_pilot()
            self.assertFalse((pathlib.Path(d)/'attempt').exists());start.assert_not_called()
            data={'raw':b'mock','runtime_source':'target','target_group_name':'Smart Pro Managed — ID-56674'}
            with mock.patch.object(app,'_execution_settings_material',return_value=data):
                app.request_first_seed_pilot()
            self.assertTrue((pathlib.Path(d)/'attempt').exists());self.assertEqual(data['raw'],b'');start.assert_called_once()
            with mock.patch.object(app,'_execution_settings_material',return_value=data):
                with self.assertRaisesRegex(RuntimeError,'first_seed_already_attempted'):
                    app.request_first_seed_pilot()

    def test_persistent_requires_exact_group(self):
        good={'runtime_source':'target','target_group_name':'Smart Pro Managed — ID-56674'}
        with mock.patch.object(app,'_execution_settings_material',return_value=good):
            self.assertEqual(app._persistent_settings_material(ID,{'runtime_source':'target'}),good)
        with mock.patch.object(app,'_execution_settings_material',return_value={**good,'target_group_name':'Smart Pro Managed — ID-86995'}):
            with self.assertRaisesRegex(RuntimeError,'assisted_seed_settings_mismatch'):
                app._persistent_settings_material(ID,{'runtime_source':'target'})
        with self.assertRaisesRegex(RuntimeError,'assisted_seed_source_not_target'):
            app._persistent_settings_material(ID,{'runtime_source':'shared'})

if __name__ == '__main__':unittest.main()
