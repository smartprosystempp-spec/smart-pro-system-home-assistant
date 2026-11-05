"""Regression checks for general, non-pilot manual stable identity reuse."""
import importlib.util
import os
from pathlib import Path
from unittest import TestCase, mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'smart-pro-managed-support' / 'app.py'

class TestManualGeneral(TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['SMART_PRO_MANAGED_VERSION'] = '3.19.10'
        spec = importlib.util.spec_from_file_location('manual_managed_app', APP)
        cls.app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.app)

    def test_general_target_stable_identity_does_not_use_migration_pilot(self):
        identity={'installation_id':'ID-12345'}
        persisted={'runtime_source':'target'}
        with mock.patch.object(self.app,'_execution_settings_material',return_value={
            'runtime_source':'target','target_group_name':'Smart Pro Managed — ID-12345'}) as settings, \
             mock.patch.object(self.app,'verify_group_migration_target_settings',side_effect=AssertionError('legacy migration must not execute')):
            result=self.app._persistent_settings_material(identity,persisted)
        self.assertEqual(result['runtime_source'],'target')
        settings.assert_called_once_with(identity)

    def test_manual_target_must_match_exact_installation(self):
        identity={'installation_id':'ID-12345'}
        with mock.patch.object(self.app,'_execution_settings_material',return_value={
            'runtime_source':'target','target_group_name':'Smart Pro Managed — ID-99999'}):
            with self.assertRaisesRegex(RuntimeError,'manual_target_settings_mismatch'):
                self.app._persistent_settings_material(identity,{'runtime_source':'target'})

    def test_no_seed_is_authorized_by_persistent_runtime(self):
        source=APP.read_text()
        self.assertIn("if prepared.get('mode') != 'reuse':",source)
        self.assertIn('persistent_identity_reuse_required',source)
        self.assertIn("if VERSION == '3.19.10' and source == 'target':",source)

    def test_old_3199_one_shot_proof_preserved(self):
        source=APP.read_text()
        self.assertIn('REUSE_PROOF_ATTEMPT_FILE',source)
        self.assertIn("VERSION=='3.19.9'",source)
        self.assertIn('start_assisted_reuse_proof()',source)

    def test_auto_boot_version_parity(self):
        cfg=(ROOT/'smart-pro-managed-support'/'config.yaml').read_text()
        self.assertIn('version: "3.19.11"',cfg)
        self.assertIn('boot: auto',cfg)
        self.assertIn('3.19.11',(ROOT/'smart-pro-managed-support'/'run.sh').read_text())
        self.assertIn('3.19.11',(ROOT/'smart-pro-managed-support'/'Dockerfile').read_text())
        self.assertIn('3.19.11',(ROOT/'.github'/'workflows'/'publish-managed-support.yml').read_text())
