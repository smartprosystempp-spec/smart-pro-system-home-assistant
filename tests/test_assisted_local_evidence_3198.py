"""Version-pinned ID-56674 local reuse evidence safety tests; offline fixtures only."""
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / 'smart-pro-managed-support' / 'app.py'
spec = importlib.util.spec_from_file_location('managed_3198_evidence', SRC)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

IDENTITY={'installation_id':'ID-56674','node_id':'SPMN-'+'A'*32,'node_secret':'dummy-test-only'}
LABEL='SPMNG-1966BA5EED8DD9B5'
DB_SHA='d'*64

class LocalEvidence3198(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        d=pathlib.Path(self.temp.name)
        self.latch_path=d/'attempt.json'; self.report_path=d/'report.json'
        latch={
            'installation_id': IDENTITY['installation_id'], 'node_id':IDENTITY['node_id'],
            'architecture':'amd64', 'scope':'single_explicit_first_seed',
            'technician_actions_authorized':False,'unattended_enabled':False
        }
        report={
            'installation_id': IDENTITY['installation_id'], 'node_id': IDENTITY['node_id'],
            'client_version':'3.19.7','architecture':'amd64',
            'status':'reported','verified':True,'result_code':'runtime_limit',
            'identity_mode':'seed','identity_db_persisted':True,
            'identity_binding_verified':True,'runtime_directory_deleted':True,
            'technician_actions_authorized':False,'identity_generation':1,
            'identity_continuity_runs':1,'identity_db_sha256_hint':DB_SHA[:12],
            'agent_label':LABEL,'started_at':1000,'ended_at':1041
        }
        self.write(self.latch_path,latch); self.write(self.report_path,report)
        state={
            'state':'ready','generation':1,'continuity_runs':1,'runtime_source':'target',
            'target_group_name':'Smart Pro Managed — ID-56674','agent_label':LABEL,'db_sha256':DB_SHA
        }
        self.patches=[
            mock.patch.object(app,'VERSION','3.19.8'),mock.patch.object(app,'ARCH','amd64'),
            mock.patch.object(app,'FIRST_SEED_ATTEMPT_FILE',self.latch_path),
            mock.patch.object(app,'CANARY_STATE_FILE',self.report_path),
            mock.patch.object(app,'read_policy',return_value={'allowed_local':True,'policy':{'installation_id':'ID-56674'}}),
            mock.patch.object(app,'get_server_state',return_value={'authorized_server':True,'valid_until':4000,'installation_id':'ID-56674','node_id':IDENTITY['node_id']}),
            mock.patch.object(app,'now_ts',return_value=2000),
            mock.patch.object(app,'_validate_persisted_mesh_identity',return_value=state),
            mock.patch.object(app,'load_unattended_control',return_value={'enabled':False}),
        ]
        for p in self.patches:
            p.start();self.addCleanup(p.stop)
    def write(self,path,data):
        path.write_text(json.dumps(data),encoding='utf-8')
        path.chmod(0o600)
    def probe(self):
        return app.assisted_local_reuse_evidence(IDENTITY)
    def test_expected_ready_is_local_only_not_native_proof(self):
        r=self.probe()
        self.assertEqual(r['stage'],'LOCAL_REUSE_EVIDENCE_READY')
        self.assertTrue(all(r['checks'].values()))
        self.assertFalse(r['binding_authorized'])
        self.assertFalse(r['broker_attested'])
        self.assertFalse(r['meshcentral_native_node_verified'])
        self.assertFalse(r['remote_agent_executed'])
    def test_missing_or_corrupt_seed_report_blocks(self):
        self.report_path.unlink()
        self.assertEqual(self.probe()['stage'],'BLOCKED_LOCAL_REUSE_CHECKS')
        self.write(self.report_path,{'verified':False})
        self.assertFalse(self.probe()['checks']['seed_receipt_verified'])
    def test_wrong_label_or_db_hint_blocks(self):
        data=json.loads(self.report_path.read_text());data['agent_label']='SPMNG-OTHERNODE'
        self.write(self.report_path,data)
        self.assertFalse(self.probe()['checks']['stable_target_provenance'])
        data['agent_label']=LABEL;data['identity_db_sha256_hint']='e'*12
        self.write(self.report_path,data)
        self.assertFalse(self.probe()['checks']['stable_target_provenance'])
    def test_seed_generation_and_target_binding_invariant(self):
        with mock.patch.object(app,'_validate_persisted_mesh_identity',return_value={'state':'ready','generation':2,'continuity_runs':2,'runtime_source':'shared','target_group_name':'wrong'}):
            self.assertEqual(self.probe()['stage'],'BLOCKED_LOCAL_REUSE_CHECKS')
    def test_local_file_symlink_denied(self):
        old=self.latch_path.with_name('old.json');self.latch_path.rename(old)
        self.latch_path.symlink_to(old)
        self.assertFalse(self.probe()['checks']['one_shot_seed_latched'])
    def test_wrong_owner_or_version_blocks_scope(self):
        self.assertEqual(app.assisted_local_reuse_evidence({**IDENTITY,'installation_id':'ID-11111'})['stage'],'NOT_IN_SCOPE')
        with mock.patch.object(app,'VERSION','3.19.7'):
            self.assertEqual(self.probe()['stage'],'NOT_IN_SCOPE')
    def test_expired_server_policy_or_unattended_blocks(self):
        with mock.patch.object(app,'get_server_state',return_value={'authorized_server':True,'valid_until':1,'installation_id':'ID-56674','node_id':IDENTITY['node_id']}):
            self.assertFalse(self.probe()['checks']['fresh_broker_authorization'])
        with mock.patch.object(app,'load_unattended_control',return_value={'enabled':True}):
            self.assertFalse(self.probe()['checks']['unattended_paused'])
    def test_runtime_start_is_hard_locked(self):
        with mock.patch.object(app,'load_identity',return_value=IDENTITY):
            with self.assertRaisesRegex(RuntimeError,'assisted_local_evidence_runtime_locked'):
                app.start_persistent_runtime()
    def test_no_secret_or_raw_db_in_report(self):
        r=self.probe()
        out=json.dumps(r)
        self.assertNotIn('node_secret',out)
        self.assertNotIn(DB_SHA,out)
        self.assertNotIn('meshagent.db',out)

if __name__=='__main__': unittest.main()
