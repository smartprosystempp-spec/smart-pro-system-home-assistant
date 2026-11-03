"""Assisted initial pairing 3.19.4, synthetic isolated HTTP handler tests."""
import importlib.util, pathlib, io, unittest
from unittest import mock
SRC=pathlib.Path(__file__).resolve().parents[1]/"smart-pro-managed-support"/"app.py"
spec=importlib.util.spec_from_file_location("paired_managed",SRC)
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
def send(code="SPM-TEST"):
 h=object.__new__(app.Handler);h.path="/pair"
 b=("csrf="+app.CSRF_TOKEN+"&pairing_code="+code).encode()
 h.headers={"Content-Length":str(len(b))};h.rfile=io.BytesIO(b)
 results=[];h._send=lambda status,*args:results.append(status)
 h.do_POST();return results
class TestAssistedPairing(unittest.TestCase):
 def test_narrow_gate(self):
  self.assertTrue(app.STABLE_POST_ACTIONS_ONLY)
  self.assertTrue(app.ASSISTED_INITIAL_PAIRING_ENABLED)
 def test_can_pair_without_identity(self):
  with mock.patch.object(app,'load_identity',return_value=None),mock.patch.object(app,'PERSISTENT_WORKER_ACTIVE',False),mock.patch.object(app,'read_policy',return_value={}),mock.patch.object(app,'render_page',return_value='page'),mock.patch.object(app,'pair_with_broker') as pair:
   self.assertEqual(send(),[200]);pair.assert_called_once_with('SPM-TEST')
 def test_existing_identity_never_replaced(self):
  with mock.patch.object(app,'load_identity',return_value={'node_id':'existing'}),mock.patch.object(app,'PERSISTENT_WORKER_ACTIVE',False),mock.patch.object(app,'read_policy',return_value={}),mock.patch.object(app,'render_page',return_value='page'),mock.patch.object(app,'pair_with_broker') as pair:
   self.assertEqual(send(),[409]);pair.assert_not_called()
 def test_running_worker_never_repaired(self):
  with mock.patch.object(app,'PERSISTENT_WORKER_ACTIVE',True),mock.patch.object(app,'read_policy',return_value={}),mock.patch.object(app,'render_page',return_value='page'),mock.patch.object(app,'pair_with_broker') as pair:
   self.assertEqual(send(),[409]);pair.assert_not_called()
 def test_invalid_csrf(self):
  with mock.patch.object(app,'read_policy',return_value={}),mock.patch.object(app,'render_page',return_value='page'),mock.patch.object(app,'pair_with_broker') as pair:
   h=object.__new__(app.Handler);h.path='/pair';b=b'csrf=wrong&pairing_code=SPM-TEST';h.headers={'Content-Length':str(len(b))};h.rfile=io.BytesIO(b);r=[];h._send=lambda status,*args:r.append(status);h.do_POST();self.assertEqual(r,[403]);pair.assert_not_called()
 def test_other_legacy_route_still_blocked(self):
  h=object.__new__(app.Handler);h.path='/candidate-promotion';b=('csrf='+app.CSRF_TOKEN).encode();h.headers={'Content-Length':str(len(b))};h.rfile=io.BytesIO(b);r=[];h._send=lambda status,*args:r.append(status)
  with mock.patch.object(app,'read_policy',return_value={}),mock.patch.object(app,'render_page',return_value='page'):
   h.do_POST();self.assertEqual(r,[409])
if __name__=='__main__':unittest.main()
