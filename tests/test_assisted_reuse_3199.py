"""Isolated 3.19.9 reuse-only proof safety gates; no remote call or MeshAgent."""
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[1]
SRC=ROOT/'smart-pro-managed-support'/'app.py'
spec=importlib.util.spec_from_file_location('managed_assisted_3199',SRC)
app=importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
IDENTITY={'installation_id':'ID-56674','node_id':'SPMN-'+'A'*32,'node_secret':'dummy'}

class ReuseProof3199(unittest.TestCase):
    def test_version_and_exact_scope(self):
        with mock.patch.object(app,'VERSION','3.19.9'),mock.patch.object(app,'ARCH','amd64'):
            self.assertFalse(app.assisted_first_seed_scope(IDENTITY))
            self.assertTrue(app.assisted_local_version())
            with mock.patch.object(app,'load_identity',return_value={**IDENTITY,'installation_id':'ID-55555'}):
                with self.assertRaisesRegex(RuntimeError,'reuse_scope_invalid'):
                    app.start_assisted_reuse_proof()
        with mock.patch.object(app,'VERSION','3.19.8'):
            with self.assertRaisesRegex(RuntimeError,'reuse_scope_invalid'):
                app.start_assisted_reuse_proof()

    def test_missing_evidence_denies_without_creating_latch(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(app,'REUSE_PROOF_ATTEMPT_FILE',pathlib.Path(d)/'attempt'),\
             mock.patch.object(app,'REUSE_PROOF_STATE_FILE',pathlib.Path(d)/'result'),\
             mock.patch.object(app,'VERSION','3.19.9'),mock.patch.object(app,'ARCH','amd64'),\
             mock.patch.object(app,'load_identity',return_value=IDENTITY),\
             mock.patch.object(app,'assisted_local_reuse_evidence',return_value={'stage':'BLOCKED_LOCAL_REUSE_CHECKS'}):
            with self.assertRaisesRegex(RuntimeError,'reuse_not_ready'):
                app.start_assisted_reuse_proof()
            self.assertFalse((pathlib.Path(d)/'attempt').exists())

    def test_one_shot_latch_written_before_worker_and_non_replayable(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(app,'REUSE_PROOF_ATTEMPT_FILE',pathlib.Path(d)/'attempt'),\
             mock.patch.object(app,'REUSE_PROOF_STATE_FILE',pathlib.Path(d)/'result'),\
             mock.patch.object(app,'DATA_DIR',pathlib.Path(d)),\
             mock.patch.object(app,'VERSION','3.19.9'),mock.patch.object(app,'ARCH','amd64'),\
             mock.patch.object(app,'load_identity',return_value=IDENTITY),\
             mock.patch.object(app,'assisted_local_reuse_evidence',return_value={'stage':'LOCAL_REUSE_EVIDENCE_READY'}),\
             mock.patch.object(app.threading,'Thread') as th:
            try:
                app.start_assisted_reuse_proof()
                assert json.loads((pathlib.Path(d)/'attempt').read_text())['first_seed'] is False
                th.return_value.start.assert_called_once()
                with self.assertRaisesRegex(RuntimeError,'reuse_already_attempted'):
                    app.start_assisted_reuse_proof()
            finally:
                app.REUSE_PROOF_WORKER_ACTIVE=False

    def test_new_settings_use_exact_target_only(self):
        fields={'MeshName':'Smart Pro Managed — ID-56674','MeshServer':'wss://support.example.com/agent.ashx','agentName':'SPMNG-1966BA5EED8DD9B5'}
        # `_execution_settings_material` reads a fresh Broker proof-scoped source;
        # at minimum the resulting target-check branch must be present and version-pinned.
        code=SRC.read_text()
        self.assertIn("assisted_reuse = VERSION == '3.19.9'",code)
        self.assertIn("material['runtime_source'] = 'target'",code)
        self.assertIn("reuse_target_only_denied",code)

    def test_first_seed_receipt_saved_separately_from_reuse_proof(self):
        code=SRC.read_text()
        worker=code[code.index('def assisted_reuse_proof_worker('):code.index('def start_connectivity_canary(',code.index('def assisted_reuse_proof_worker('))]
        self.assertIn('save_reuse_proof_state(',worker)
        self.assertNotIn('save_canary_state(',worker)
        self.assertIn("identity_mode='reuse'",worker)
        self.assertNotIn('first_seed_pilot_readiness(',worker)
        self.assertIn("_copy_persisted_identity_into_runtime",worker)
        self.assertIn("_terminate_process_group_before",worker)

    def test_unattended_and_legacy_execution_still_blocked(self):
        with mock.patch.object(app,'VERSION','3.19.9'),mock.patch.object(app,'ARCH','amd64'),mock.patch.object(app,'load_identity',return_value=IDENTITY):
            with self.assertRaisesRegex(RuntimeError,'assisted_local_evidence_runtime_locked'):
                app.start_persistent_runtime()
        src=SRC.read_text()
        self.assertIn("(is_first_seed or is_canary or is_persistent_start)",src)
        self.assertIn("is_reuse_proof",src)

    def test_no_raw_secret_persisted_in_reuse_attempt(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(app,'REUSE_PROOF_ATTEMPT_FILE',pathlib.Path(d)/'attempt'),\
             mock.patch.object(app,'REUSE_PROOF_STATE_FILE',pathlib.Path(d)/'result'),\
             mock.patch.object(app,'DATA_DIR',pathlib.Path(d)),mock.patch.object(app,'VERSION','3.19.9'),\
             mock.patch.object(app,'ARCH','amd64'),mock.patch.object(app,'load_identity',return_value=IDENTITY),\
             mock.patch.object(app,'assisted_local_reuse_evidence',return_value={'stage':'LOCAL_REUSE_EVIDENCE_READY'}),\
             mock.patch.object(app.threading,'Thread'):
            try:
                app.start_assisted_reuse_proof()
                data=(pathlib.Path(d)/'attempt').read_text()
                self.assertNotIn('dummy',data)
                self.assertNotIn('node_secret',data)
                self.assertEqual(json.loads(data)['installation_id'],'ID-56674')
            finally:app.REUSE_PROOF_WORKER_ACTIVE=False

if __name__=='__main__':unittest.main()
