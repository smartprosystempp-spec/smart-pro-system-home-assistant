"""Isolated, offline security regression tests. No Broker or MeshCentral requests."""
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from contextlib import ExitStack
from unittest import mock

SRC=pathlib.Path(__file__).resolve().parents[1]/'smart-pro-managed-support'/'app.py'
spec=importlib.util.spec_from_file_location('first_seed_test',SRC)
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
NODE='SPMN-'+'A'*32
IDENT={'installation_id':'ID-28422','node_id':NODE,'node_secret':'test-not-real'}
POLICY={'allowed_local':True,'policy':{'installation_id':'ID-28422'}}
SERVER={'authorized_server':True,'installation_id':'ID-28422','node_id':NODE,'valid_until':9999999999}

def post(path,confirmed=None):
 h=object.__new__(app.Handler);h.path='/'+path
 parts=['csrf='+app.CSRF_TOKEN]
 if confirmed is not None:parts.append('confirm_first_seed='+confirmed)
 raw='&'.join(parts).encode();h.headers={'Content-Length':str(len(raw))};h.rfile=io.BytesIO(raw)
 calls=[];h._send=lambda code,*args:calls.append(code);h.do_POST();return calls

class Pilot(unittest.TestCase):
 def setUp(self):
  self.stack=ExitStack();p=self.stack.enter_context
  for name,val in [('ARCH','amd64'),('load_identity',None),('read_policy',None)]:
   if name=='ARCH':p(mock.patch.object(app,name,val))
  p(mock.patch.object(app,'load_identity',return_value=IDENT))
  p(mock.patch.object(app,'read_policy',return_value=POLICY))
  p(mock.patch.object(app,'get_server_state',return_value=SERVER))
  p(mock.patch.object(app,'get_mesh_identity_status',return_value={'state':'not_seeded'}))
  p(mock.patch.object(app,'load_unattended_control',return_value={'enabled':False}))
  p(mock.patch.object(app,'PROCESS_SHUTDOWN',new=mock.Mock(is_set=lambda:False)))
  p(mock.patch.object(app,'render_page',return_value='page'))
  for var in ('CANARY_WORKER_ACTIVE','PERSISTENT_WORKER_ACTIVE','FIRST_DEVICE_EXECUTION_WORKER_ACTIVE','MIGRATION_CANARY_WORKER_ACTIVE','IDENTITY_RESEED_WORKER_ACTIVE','CANDIDATE_RECONNECT_WORKER_ACTIVE','PROMOTION_WORKER_ACTIVE'):
   p(mock.patch.object(app,var,False))
  t=p(tempfile.TemporaryDirectory());self.tmp=pathlib.Path(t)
  p(mock.patch.object(app,'DATA_DIR',self.tmp))
  p(mock.patch.object(app,'FIRST_SEED_ATTEMPT_FILE',self.tmp/'one-shot.json'))
  p(mock.patch.object(app,'CANARY_STATE_FILE',self.tmp/'canary.json'))
 def tearDown(self):self.stack.close()
 def deny(self):self.assertFalse(app.first_seed_pilot_readiness()[0])
 def test_good_baseline(self):self.assertTrue(app.first_seed_pilot_readiness()[0])
 def test_not_other_installations(self):
  with mock.patch.object(app,'load_identity',return_value={'installation_id':'ID-95948','node_id':NODE}):self.deny()
 def test_not_aarch64(self):
  with mock.patch.object(app,'ARCH','aarch64'):self.deny()
 def test_policy_mismatch(self):
  with mock.patch.object(app,'read_policy',return_value={'allowed_local':True,'policy':{'installation_id':'ID-34973'}}):self.deny()
 def test_expired_authorization(self):
  with mock.patch.object(app,'get_server_state',return_value={**SERVER,'valid_until':1}):self.deny()
 def test_broker_node_mismatch(self):
  with mock.patch.object(app,'get_server_state',return_value={**SERVER,'node_id':'SPMN-'+'B'*32}):self.deny()
 def test_already_seeded(self):
  with mock.patch.object(app,'get_mesh_identity_status',return_value={'state':'ready'}):self.deny()
 def test_partial_identity_blocks(self):
  with mock.patch.object(app,'get_mesh_identity_status',return_value={'state':'blocked'}):self.deny()
 def test_existing_attempt_blocks(self):
  app.FIRST_SEED_ATTEMPT_FILE.write_text('{}');self.deny()
 def test_existing_canary_record_blocks(self):
  app.CANARY_STATE_FILE.write_text('{}');self.deny()
 def test_unattended_blocks(self):
  with mock.patch.object(app,'load_unattended_control',return_value={'enabled':True}):self.deny()
 def test_worker_blocks(self):
  with mock.patch.object(app,'CANARY_WORKER_ACTIVE',True):self.deny()
 def test_confirmation_required_server_side(self):
  with mock.patch.object(app,'request_first_seed_pilot') as fn:
   self.assertEqual(post('first-identity-enrollment'),[409]);self.assertEqual(post('first-identity-enrollment','ID-95948'),[409]);fn.assert_not_called()
 def test_confirmed_request_calls_pilot_once(self):
  with mock.patch.object(app,'request_first_seed_pilot') as fn:
   self.assertEqual(post('first-identity-enrollment','ID-28422'),[202]);fn.assert_called_once()
 def test_historical_canary_locked(self):
  with mock.patch.object(app,'start_connectivity_canary') as fn:
   self.assertEqual(post('identity-continuity-canary'),[409]);fn.assert_not_called()
 def test_one_shot_marker_blocks_replay(self):
  with mock.patch.object(app,'start_connectivity_canary') as fn:
   app.request_first_seed_pilot();fn.assert_called_once()
   x=json.loads(app.FIRST_SEED_ATTEMPT_FILE.read_text());self.assertEqual(x['installation_id'],'ID-28422')
   self.assertEqual(app.FIRST_SEED_ATTEMPT_FILE.stat().st_mode&0o777,0o600)
   self.deny()
   with self.assertRaises(RuntimeError):app.request_first_seed_pilot()
   fn.assert_called_once()
 def test_persistent_start_fail_closed_if_seed_unverified(self):
  app.FIRST_SEED_ATTEMPT_FILE.write_text('{}')
  with mock.patch.object(app,'get_mesh_identity_status',return_value={'state':'ready'}),mock.patch.object(app,'load_canary_state',return_value={'status':'failed','identity_mode':'seed'}):
   with self.assertRaisesRegex(RuntimeError,'first_seed_report_not_verified'):app.start_persistent_runtime()
 def test_persistent_needs_runtime_limit_and_cleanup(self):
  app.FIRST_SEED_ATTEMPT_FILE.write_text('{}')
  good={'status':'reported','verified':True,'identity_mode':'seed','identity_db_persisted':True,'runtime_directory_deleted':True,'result_code':'runtime_limit'}
  with mock.patch.object(app,'get_mesh_identity_status',return_value={'state':'ready'}):
   for field,wrong in [('result_code','agent_exit'),('runtime_directory_deleted',False),('verified',False),('identity_mode','reuse')]:
    with mock.patch.object(app,'load_canary_state',return_value={**good,field:wrong}):
     with self.assertRaisesRegex(RuntimeError,'first_seed_report_not_verified'):app.start_persistent_runtime()

if __name__=='__main__':unittest.main()
