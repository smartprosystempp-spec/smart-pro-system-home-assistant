"""0.6.1 read-only, failure-classifying handoff preflight QA."""
import unittest
from unittest.mock import patch
import app
from consent_qa import issue, consume
from secure_handoff_qa import HandoffError

class ReadOnlyProbeTests(unittest.TestCase):
    def test_probe_requires_own_approval_and_does_not_authorize_create(self):
        probe = issue('admin-test',now=100.0,action='handoff_probe')
        self.assertFalse(consume(probe,'admin-test','ΠΑΡΑΔΟΣΗ',action='handoff_probe',now=101.0))
        probe = issue('admin-test',now=102.0,action='handoff_probe')
        self.assertTrue(consume(probe,'admin-test','',action='handoff_probe',now=103.0))
        self.assertFalse(consume(probe,'admin-test','',action='handoff_probe',now=104.0))
        self.assertFalse(consume(probe,'admin-test','ΠΑΡΑΔΟΣΗ',action='handoff_create',now=104.0))

    def test_ui_read_only_probe_does_not_expose_to_normal_user(self):
        good=app.render_page({'is_admin':True,'reason':'ok'}, lab_state='absent',
                             handoff_probe_token='hidden-probe-token', handoff_token='hidden-create-token').decode()
        self.assertIn('lab-handoff-preflight-form',good)
        self.assertIn('Έλεγχος παράδοσης χωρίς δημιουργία',good)
        self.assertIn('lab-handoff-create-form',good)
        bad=app.render_page({'is_admin':False,'reason':'blocked'}, lab_state='absent',
                            handoff_probe_token='hidden-probe-token').decode()
        self.assertNotIn('lab-handoff-preflight-form',bad)
        self.assertNotIn('hidden-probe-token',bad)

    def test_preflight_never_requires_ha_write(self):
        # The preflight module only sends ticket-poll and returns a validated
        # public key, and does not reference credential creation or password.
        from pathlib import Path
        src=Path(app.__file__).read_text()
        # The new probe branch calls only preflight(), not deliver().
        part=src.split("if action == 'handoff_probe':",1)[1].split("if not ROUND_TRIP_LOCK.acquire",1)[0]
        self.assertIn('preflight(payload',part)
        self.assertNotIn('create_lab',part)
        self.assertNotIn('deliver_laboratory_account',part)

if __name__=='__main__':unittest.main()

class ReadOnlyLocalHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import threading
        cls.server=app.Server(('127.0.0.1',0),app.Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.base=f'http://127.0.0.1:{cls.server.server_port}'
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(timeout=5)
    def request(self, token, *, origin=True):
        import json,urllib.request,urllib.error
        url=self.base+'/lab-handoff-preflight'
        header={'Content-Type':'application/json','X-Smart-Pro-QA-Action':'v1',
                'X-Remote-User-Id':'admin-test'}
        if origin:header['Origin']=self.base
        req=urllib.request.Request(url,method='POST',headers=header,
                 data=json.dumps({'csrf':token,'ticket':'ID-75236:'+'a'*64}).encode())
        try:
            with urllib.request.urlopen(req,timeout=5) as r:
                return r.status, r.read().decode(), r.headers.get('Content-Type')
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(),e.headers.get('Content-Type')

    def test_preflight_success_returns_safe_code_without_create(self):
        token=issue('admin-test',action='handoff_probe')
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'preflight',return_value={'public_key':b'x'*32}) as verify, \
             patch.object(app,'deliver_laboratory_account',side_effect=AssertionError('unexpected HA write')):
            status, body, ctype=self.request(token)
        self.assertEqual(status,200)
        self.assertIn('application/json',ctype)
        self.assertEqual(__import__('json').loads(body),{'code':'handoff_preflight_ready_no_write'})
        verify.assert_called_once()

    def test_preflight_invalid_ticket_returns_safe_code_without_create(self):
        token=issue('admin-test',action='handoff_probe')
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'preflight',side_effect=HandoffError('handoff_preflight_denied_no_write')), \
             patch.object(app,'deliver_laboratory_account',side_effect=AssertionError('unexpected HA write')):
            status, body, _=self.request(token)
        self.assertEqual(status,200)
        self.assertEqual(__import__('json').loads(body),{'code':'handoff_preflight_denied_no_write'})

    def test_preflight_origin_denied_no_action(self):
        token=issue('admin-test',action='handoff_probe')
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'preflight',side_effect=AssertionError('preflight forbidden')):
            status, body, _=self.request(token,origin=False)
        self.assertEqual(status,403)
        self.assertEqual(body,'origin_gate_denied_no_write')
