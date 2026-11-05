"""Offline, exact-group first identity enrollment checks for 3.19.11, all IDs."""
import importlib.util
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'smart-pro-managed-support'/'app.py'
with mock.patch.dict(os.environ, {'SMART_PRO_MANAGED_VERSION':'3.19.11','SMART_PRO_MANAGED_ARCH':'amd64'}):
    spec=importlib.util.spec_from_file_location('managed_general_seed_31911',SOURCE)
    app=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)

NODE='SPMN-'+'E'*32

def fixture(ref):
    return {'installation_id':ref, 'node_id':NODE, 'node_secret':'dummy'}

class GeneralSeedContract(TestCase):
    def test_all_valid_installations_scoped_not_specific_allowlist(self):
        for ref in ['ID-00001','ID-12345','ID-28422','ID-56674','ID-86995','ID-99999']:
            with self.subTest(ref=ref):
                self.assertTrue(app.assisted_first_seed_scope(fixture(ref)))
        for ref in ['ID-12','ID-1234','ID-123456','NOT-12345','ID-1234A']:
            self.assertFalse(app.assisted_first_seed_scope(fixture(ref)))
        with mock.patch.object(app,'VERSION','3.19.10'):
            self.assertFalse(app.assisted_first_seed_scope(fixture('ID-12345')))

    def test_first_seed_readiness_and_second_attempt_fail_closed(self):
        ref='ID-54321'
        with TemporaryDirectory() as path, \
             mock.patch.object(app,'load_identity',return_value=fixture(ref)), \
             mock.patch.object(app,'read_policy',return_value={'allowed_local':True,'policy':{'installation_id':ref}}), \
             mock.patch.object(app,'get_server_state',return_value={'authorized_server':True,'valid_until':app.now_ts()+300,'installation_id':ref,'node_id':NODE}), \
             mock.patch.object(app,'get_mesh_identity_status',return_value={'state':'not_seeded'}), \
             mock.patch.object(app,'FIRST_SEED_ATTEMPT_FILE',Path(path)/'attempt'), \
             mock.patch.object(app,'CANARY_STATE_FILE',Path(path)/'canary'), \
             mock.patch.object(app,'load_unattended_control',return_value={'enabled':False}):
            self.assertTrue(app.first_seed_pilot_readiness()[0])
            (Path(path)/'attempt').write_text('attempt')
            self.assertFalse(app.first_seed_pilot_readiness()[0])

    def test_missing_or_wrong_group_denied_before_persistent_attempt(self):
        ref='ID-54321'
        with TemporaryDirectory() as path, \
             mock.patch.object(app,'first_seed_pilot_readiness',return_value=(True,'ok')), \
             mock.patch.object(app,'load_identity',return_value=fixture(ref)), \
             mock.patch.object(app,'DATA_DIR',Path(path)), \
             mock.patch.object(app,'FIRST_SEED_ATTEMPT_FILE',Path(path)/'attempt'), \
             mock.patch.object(app,'start_connectivity_canary') as canary:
            for group in ('Smart Pro Managed Support','Smart Pro Managed — ID-99999'):
                with self.subTest(group=group), mock.patch.object(app,'_execution_settings_material',return_value={
                        'runtime_source':'target','target_group_name':group,'raw':b'placeholder'}):
                    with self.assertRaisesRegex(RuntimeError, 'assisted_seed_preflight_denied'):
                        app.request_first_seed_pilot()
                    self.assertFalse((Path(path)/'attempt').exists())
                    canary.assert_not_called()
            data={'runtime_source':'target','target_group_name':f'Smart Pro Managed — {ref}','raw':b'placeholder'}
            with mock.patch.object(app,'_execution_settings_material',return_value=data):
                app.request_first_seed_pilot()
            self.assertTrue((Path(path)/'attempt').exists())
            self.assertEqual(data['raw'],b'')
            canary.assert_called_once()

    def test_continuous_reuse_never_reseeds(self):
        ref='ID-54321'
        with mock.patch.object(app,'_execution_settings_material',return_value={
            'runtime_source':'target','target_group_name':f'Smart Pro Managed — {ref}'}):
            self.assertEqual(app._persistent_settings_material(fixture(ref),{'runtime_source':'target'})['runtime_source'],'target')
            with self.assertRaisesRegex(RuntimeError,'assisted_seed_source_not_target'):
                app._persistent_settings_material(fixture(ref),{'runtime_source':'shared'})
        content=SOURCE.read_text()
        self.assertIn('persistent_identity_reuse_required',content)
        self.assertIn('GENERAL_FIRST_SEED_VERSION = "3.19.11"',content)
