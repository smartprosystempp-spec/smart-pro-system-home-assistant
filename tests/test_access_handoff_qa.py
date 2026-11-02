import base64
import json
import unittest
from unittest.mock import patch

from secure_handoff_qa import (
    CONTRACT, TICKET_PATTERN, HandoffError, preflight,
    deliver_laboratory_account,
)
import app
from consent_qa import issue,consume,attempted,allow_one_attempt

INSTALL='ID-75236'
TICKET=INSTALL+':'+('a'*64)
INFO={'contract':CONTRACT,'status':'queued','installation_id':INSTALL,
      'request_id':'b'*32,'challenge':'c'*64,'public_key':base64.b64encode(bytes(range(32))).decode(),
      'expires_at':1000+500}

class HandoffQATests(unittest.TestCase):
    def test_ticket_pattern(self):
        self.assertIsNotNone(TICKET_PATTERN.fullmatch(TICKET))
        for value in ('ID-95948:'+'a'*63, 'ID-75236:'+('B'*64),
                      'ID-75236:'+('a'*64)+'x', 'ID-75236/evil:'+'a'*64,
                      'ID-75236:'+('a'*62)+'\n'):
            self.assertIsNone(TICKET_PATTERN.fullmatch(value))

    def test_preflight_validation_before_ha_create(self):
        called=[]
        def transport(route,payload):
            called.append((route,payload))
            return dict(INFO)
        val=preflight(TICKET,transport=transport,now=1000)
        self.assertEqual(val['installation_id'],INSTALL)
        self.assertEqual(len(val['public_key']),32)
        self.assertEqual(called[0][0],'ticket-poll')
        self.assertNotIn('password',called[0][1])

    def test_unsafe_reply_fails_closed(self):
        bads=[{**INFO,'installation_id':'ID-95948'},
              {**INFO,'expires_at':900}, {**INFO,'expires_at':5000},
              {**INFO,'public_key':'!!!'}, {**INFO,'request_id':'z'*32},
              {**INFO,'status':'received'},
              {**INFO,'challenge':'C'*64},
              {**INFO,'public_key':base64.b64encode(b'x').decode()}]
        for b in bads:
            with self.subTest(b=b):
                with self.assertRaises(HandoffError):
                    preflight(TICKET,transport=lambda *_:b,now=1000)

    def test_create_never_runs_when_preflight_fails(self):
        writes=[]
        def create(**kwargs):
            writes.append(kwargs)
            raise AssertionError('Core mutation attempted')
        with self.assertRaises(HandoffError):
            deliver_laboratory_account(TICKET,supervisor_token='fake',
                preflight_fn=lambda _:(_ for _ in ()).throw(HandoffError('denied')),
                create_fn=create,seal_fn=lambda *_:b'x'*49)
        self.assertEqual(writes,[])

    def test_missing_crypto_fails_before_creation(self):
        writes=[]
        def create(**kwargs):writes.append(kwargs)
        with self.assertRaisesRegex(HandoffError,'crypto_unavailable_no_write'):
            deliver_laboratory_account(TICKET,supervisor_token='fake',
                preflight_fn=lambda _:preflight(TICKET,transport=lambda *_:INFO,now=1000),
                create_fn=create,seal_fn=lambda *_:b'')
        self.assertEqual(writes,[])

    def test_delivery_contains_no_plaintext_and_binds_installation(self):
        calls=[]; writes=[]
        password='test-random-private-secret-'+'K'*48
        def transport(route,payload):
            calls.append((route,payload))
            if route=='ticket-deliver':
                self.assertEqual(payload['installation_id'],INSTALL)
                self.assertEqual(payload['ticket'],'a'*64)
                self.assertEqual(payload['request_id'],'b'*32)
                self.assertEqual(payload['challenge'],'c'*64)
                self.assertEqual(payload['contract'],CONTRACT)
                self.assertNotIn(password,json.dumps(payload))
                return {'contract':CONTRACT,'status':'received'}
            raise AssertionError(route)
        def create(**kwargs):
            writes.append(kwargs)
            return {'code':'qa_login_admin_created_credentials_linked',
                    'username':'smartpro_qa_login_lab','password':password}
        def seal(pub,plaintext):
            self.assertEqual(pub,bytes(range(32)))
            if plaintext==b'qa-crypto-precheck':return b'x'*50
            decoded=json.loads(plaintext)
            self.assertEqual(decoded['installation_id'],INSTALL)
            self.assertEqual(decoded['password'],password)
            self.assertEqual(set(decoded),{'contract','installation_id','request_id','username','password'})
            return b'y'*100  # fake opaque sealed output; actual libsodium interoperability tested separately.
        code=deliver_laboratory_account(TICKET,supervisor_token='supervisor-fake',
          preflight_fn=lambda _:preflight(TICKET,transport=lambda *_:INFO,now=1000),
          create_fn=create,transport=transport,now=1300,seal_fn=seal)
        self.assertEqual(code,'handoff_real_qa_admin_created_and_encrypted_received')
        self.assertEqual(len(writes),1)
        self.assertEqual(len(calls),1)

    def test_delivery_uncertain_no_retry(self):
        calls=[]
        def create(**kwargs):calls.append('create');return {
           'code':'qa_login_admin_created_credentials_linked',
           'username':'smartpro_qa_login_lab','password':'X'*48}
        with self.assertRaisesRegex(HandoffError,'delivery_uncertain_check_both_sides'):
            deliver_laboratory_account(TICKET,supervisor_token='fake',
              preflight_fn=lambda _:preflight(TICKET,transport=lambda *_:INFO,now=1000),
              create_fn=create,transport=lambda *_:(_ for _ in ()).throw(OSError('network')),
              now=1300,seal_fn=lambda *_:b'y'*60)
        self.assertEqual(calls,['create'])

    def test_consent_handoff_scoped(self):
        token=issue('demo-user',now=123.0,action='handoff_create')
        self.assertFalse(consume(token,'demo-user','ΣΥΝΔΕΣΗ',action='handoff_create',now=124.0))
        token=issue('demo-user',now=124.0,action='handoff_create')
        self.assertTrue(consume(token,'demo-user','ΠΑΡΑΔΟΣΗ',action='handoff_create',now=125.0))
        self.assertFalse(consume(token,'demo-user','ΠΑΡΑΔΟΣΗ',action='handoff_create',now=126.0))
        token=issue('demo-user',now=127.0,action='handoff_create')
        self.assertFalse(consume(token,'other-user','ΠΑΡΑΔΟΣΗ',action='handoff_create',now=128.0))

    def test_ui_protected_new_form_not_legacy_login(self):
        page=app.render_page({'is_admin':True,'reason':'ok'},retained_state='absent',
                             lab_state='absent',handoff_token='test-csrf').decode()
        self.assertIn('lab-handoff-create-form',page)
        self.assertIn('ΠΑΡΑΔΟΣΗ',page)
        self.assertNotIn('id="lab-login-create-form"',page)
        denied=app.render_page({'is_admin':False,'reason':'blocked'},
                               lab_state='absent',handoff_token='test-csrf').decode()
        self.assertNotIn('lab-handoff-create-form',denied)

if __name__=='__main__':unittest.main()
