"""Isolated tests for one retained, non-login HA QA administrator and revocation.

NO live HA requests. Mock Core and real localhost sockets only.
"""
from __future__ import annotations

import http.client
import json
import pathlib
import sys
import threading
import unittest
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'smart-pro-access-preflight'))
import app
import consent_qa
import persistent_qa as pqa
import core_session_qa

ADMIN='a'*32

class FakeCore:
    def __init__(self, users=None):
        self.users = list(users) if users is not None else [
            dict(id=ADMIN,name='Owner',is_active=True,is_owner=True,
                 system_generated=False,local_only=False,group_ids=['system-admin'],credentials=[])]
        self.calls=[]
        self.failure=None
        self.unexpected_user_flags=None
        self.bad_create_result=False
    def __enter__(self):return self
    def __exit__(self,*_):pass
    def command(self, cmd,**params):
        self.calls.append((cmd,params))
        if self.failure == cmd:raise core_session_qa.RoundTripError('simulated')
        if cmd=='config/auth/list':return [dict(u) for u in self.users]
        if cmd=='config/auth/create':
            user=dict(id='b'*32,name=params['name'],is_active=True,is_owner=False,
                      system_generated=False,local_only=params['local_only'],
                      group_ids=params['group_ids'],credentials=[])
            if self.unexpected_user_flags:user.update(self.unexpected_user_flags)
            self.users.append(user)
            return {} if self.bad_create_result else {'user':user}
        if cmd=='config/auth/delete':
            self.users=[u for u in self.users if u['id'] != params['user_id']]
            return {}
        raise AssertionError('unknown Core command '+cmd)

def retained():
    return dict(id='b'*32,name=pqa.NAME,is_owner=False,is_active=True,
                system_generated=False,local_only=True,group_ids=['system-admin'],credentials=[])

class PersistentLifecycleTests(unittest.TestCase):
    def test_create_stays_in_home_assistant_after_session_exit(self):
        f=FakeCore()
        code=pqa.create_retained(supervisor_token='x'*50,session_factory=lambda _:f)
        self.assertEqual(code,'qa_retained_admin_created_no_login')
        self.assertEqual(len(f.users),2)
        self.assertEqual([x[0] for x in f.calls],
                         ['config/auth/list','config/auth/create','config/auth/list'])
        self.assertEqual(pqa.inspect_retained(supervisor_token='x'*50,session_factory=lambda _:f),
                         'retained_no_login')
        self.assertEqual(f.users[1]['credentials'],[])
        self.assertEqual(f.users[1]['local_only'],True)
        self.assertEqual(f.users[1]['group_ids'],['system-admin'])
        self.assertFalse(f.users[1]['is_owner'])

    def test_revoke_requires_exact_target_and_confirms_absence(self):
        f=FakeCore()
        f.users.append(retained())
        code=pqa.revoke_retained(supervisor_token='x'*50,session_factory=lambda _:f)
        self.assertEqual(code,'qa_retained_admin_revoked_verified')
        self.assertEqual(len(f.users),1)
        self.assertEqual([x[0] for x in f.calls],
                         ['config/auth/list','config/auth/delete','config/auth/list'])
        self.assertEqual(f.calls[1][1],{'user_id':'b'*32})

    def test_revoke_absent_does_not_call_delete(self):
        f=FakeCore()
        self.assertEqual(pqa.revoke_retained(supervisor_token='x'*50,
                                            session_factory=lambda _:f),
                         'qa_retained_admin_already_absent')
        self.assertEqual([c for c,_ in f.calls],['config/auth/list'])

    def test_creation_refuses_existing_name_no_duplicate(self):
        f=FakeCore()
        f.users.append(retained())
        with self.assertRaisesRegex(pqa.RetainedAccountError,'already_exists'):
            pqa.create_retained(supervisor_token='x'*50,session_factory=lambda _:f)
        self.assertEqual([c for c,_ in f.calls],['config/auth/list'])

    def test_creation_refuses_reserved_prefix_variant(self):
        f=FakeCore()
        f.users.append(dict(retained(),name=pqa.NAME+' UNKNOWN'))
        with self.assertRaises(pqa.RetainedAccountError):
            pqa.create_retained(supervisor_token='x'*50,session_factory=lambda _:f)
        self.assertEqual([c for c,_ in f.calls],['config/auth/list'])

    def test_revoke_denies_owner_or_credentials_or_modified_role(self):
        changes=[{'is_owner':True},{'system_generated':True},{'credentials':[{'type':'homeassistant'}]},
                 {'local_only':False},{'group_ids':['system-users']},
                 {'group_ids':['system-admin','system-users']},
                 {'name':pqa.NAME+' evil'}]
        for change in changes:
            with self.subTest(change=change):
                f=FakeCore()
                f.users.append(dict(retained(),**change))
                with self.assertRaisesRegex(pqa.RetainedAccountError,'manual_review'):
                    pqa.revoke_retained(supervisor_token='x'*50,session_factory=lambda _:f)
                self.assertFalse(any(c=='config/auth/delete' for c,_ in f.calls))

    def test_revoke_multiple_possible_targets_denies(self):
        f=FakeCore()
        f.users.extend([retained(),dict(retained(),id='c'*32)])
        with self.assertRaisesRegex(pqa.RetainedAccountError,'manual_review'):
            pqa.revoke_retained(supervisor_token='x'*50,session_factory=lambda _:f)
        self.assertFalse(any(c=='config/auth/delete' for c,_ in f.calls))

    def test_bad_created_permissions_does_not_claim_pass(self):
        f=FakeCore()
        f.unexpected_user_flags={'group_ids':['system-users']}
        with self.assertRaisesRegex(pqa.RetainedAccountError,'validation_failed'):
            pqa.create_retained(supervisor_token='x'*50,session_factory=lambda _:f)
        self.assertEqual(len(f.users),2)

    def test_uncertain_created_id_keeps_user_and_prevents_retry(self):
        f=FakeCore()
        f.bad_create_result=True
        with self.assertRaisesRegex(pqa.RetainedAccountError,'uncertain_inspect_users'):
            pqa.create_retained(supervisor_token='x'*50,session_factory=lambda _:f)
        self.assertEqual(len(f.users),2)
        with self.assertRaisesRegex(pqa.RetainedAccountError,'already_exists'):
            pqa.create_retained(supervisor_token='x'*50,session_factory=lambda _:f)
        self.assertEqual(sum(c=='config/auth/create' for c,_ in f.calls),1)

    def test_revoke_failure_no_false_claim(self):
        f=FakeCore(); f.users.append(retained());f.failure='config/auth/delete'
        with self.assertRaisesRegex(pqa.RetainedAccountError,'uncertain_check_users'):
            pqa.revoke_retained(supervisor_token='x'*50,session_factory=lambda _:f)
        self.assertEqual(len(f.users),2)

    def test_no_target_readback_fails_closed(self):
        f=FakeCore();f.failure='config/auth/list'
        self.assertEqual(pqa.inspect_retained(supervisor_token='x'*50,
                            session_factory=lambda _:f),'readback_unavailable')
        with self.assertRaises(pqa.RetainedAccountError):
            pqa.create_retained(supervisor_token='x'*50,session_factory=lambda _:f)

    def test_no_password_username_or_provider_command(self):
        f=FakeCore();pqa.create_retained(supervisor_token='x'*50,session_factory=lambda _:f)
        cmd_string=str(f.calls).lower()
        self.assertNotIn('password',cmd_string)
        self.assertNotIn('username',cmd_string)
        self.assertNotIn('auth_provider',cmd_string)
        self.assertNotIn('portal',cmd_string)

    def test_view_only_non_admin_has_no_forms(self):
        page=app.render_page({'is_admin':False,'reason':'non_admin'},
                             retained_state='retained_no_login',revoke_token='secret').decode()
        self.assertNotIn('revoke-admin',page)
        self.assertNotIn('retain-admin',page)
        self.assertNotIn('secret',page)

    def test_create_form_only_absent_and_revoke_only_retained(self):
        yes={'is_admin':True,'reason':'ok'}
        a=app.render_page(yes,retained_state='absent',create_token='secret-create').decode()
        b=app.render_page(yes,retained_state='retained_no_login',revoke_token='secret-revoke').decode()
        c=app.render_page(yes,retained_state='review_required',create_token='x',revoke_token='y').decode()
        self.assertIn('action="retain-admin"',a)
        self.assertNotIn('action="revoke-admin"',a)
        self.assertIn('action="revoke-admin"',b)
        self.assertNotIn('action="retain-admin"',b)
        self.assertNotIn('action="retain-admin"',c)
        self.assertNotIn('action="revoke-admin"',c)

    def test_separate_authorization_tokens_and_phrases(self):
        with consent_qa._lock:
            consent_qa._issued.clear();consent_qa._attempted=set()
        create=consent_qa.issue(ADMIN,now=100,action='create')
        revoke=consent_qa.issue(ADMIN,now=100,action='revoke')
        self.assertFalse(consent_qa.consume(create,ADMIN,'ΑΝΑΚΛΗΣΗ',action='revoke',now=101))
        self.assertTrue(consent_qa.consume(revoke,ADMIN,'ΑΝΑΚΛΗΣΗ',action='revoke',now=101))
        self.assertFalse(consent_qa.consume(revoke,ADMIN,'ΑΝΑΚΛΗΣΗ',action='revoke',now=102))

class HttpBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=app.Server(('127.0.0.1',0),app.Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start();cls.port=cls.server.server_port
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(5)
    def setUp(self):
        with consent_qa._lock:
            consent_qa._issued.clear();consent_qa._attempted=set()
    def req(self,path='/retain-admin',*,method='POST',body=None,extra=None,origin='valid',action='create'):
        host=f'127.0.0.1:{self.port}'
        headers={'Content-Type':'application/json','X-Remote-User-Id':ADMIN,
                 'X-Remote-User-Groups':'system-admin','X-Smart-Pro-QA-Action':'v1'}
        if origin=='valid':headers['Origin']='http://'+host
        elif origin=='invalid':headers['Origin']='https://outside.invalid'
        if extra:headers.update(extra)
        if body is None:
            token=consent_qa.issue(ADMIN,action=action)
            confirm=consent_qa.APPROVAL_WORD if action=='create' else consent_qa.REVOKE_WORD
            body=json.dumps({'csrf':token,'confirm':confirm},ensure_ascii=False)
        conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=5)
        conn.request(method,path,body=body.encode('utf8') if isinstance(body,str) else body,headers=headers)
        r=conn.getresponse();buf=r.read();status=r.status;conn.close()
        return status,buf
    def test_direct_network_spoofed_headers_never_run_writer(self):
        with patch.object(app,'create_retained') as create:
            status,_=self.req(extra={'X-Forwarded-For':'172.30.32.2'})
            self.assertEqual(status,403);create.assert_not_called()
    def test_nonadmin_cannot_create_even_if_core_reads_fail(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':False,'reason':'non_admin'}),\
             patch.object(app,'create_retained') as create:
            status,_=self.req()
            self.assertEqual(status,403);create.assert_not_called()
    def test_core_admin_create_valid_approval_once(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}),\
             patch.object(app,'create_retained',return_value='qa_retained_admin_created_no_login') as create:
            status,buf=self.req()
            self.assertEqual(status,200)
            self.assertEqual(json.loads(buf),{'code':'qa_retained_admin_created_no_login'})
            create.assert_called_once()
            status,_=self.req()
            self.assertEqual(status,409);create.assert_called_once()
    def test_revoke_honors_own_scoped_approval(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}),\
             patch.object(app,'revoke_retained',return_value='qa_retained_admin_revoked_verified') as revoke:
            status,buf=self.req(path='/revoke-admin',action='revoke')
            self.assertEqual(status,200)
            self.assertEqual(json.loads(buf),{'code':'qa_retained_admin_revoked_verified'})
            revoke.assert_called_once()
    def test_create_token_cannot_approve_revoke(self):
        token=consent_qa.issue(ADMIN,action='create')
        body=json.dumps({'csrf':token,'confirm':'ΔΗΜΙΟΥΡΓΙΑ'},ensure_ascii=False)
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}),\
             patch.object(app,'revoke_retained') as revoke:
            status,_=self.req(path='/revoke-admin',body=body,action='revoke')
            self.assertEqual(status,403);revoke.assert_not_called()
    def test_cross_origin_and_missing_action_denied(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}),\
             patch.object(app,'create_retained') as create:
            self.assertEqual(self.req(origin='invalid')[0],403)
            self.assertEqual(self.req(extra={'X-Smart-Pro-QA-Action':''})[0],403)
            self.assertEqual(self.req(extra={'Sec-Fetch-Site':'cross-site'})[0],403)
            create.assert_not_called()
    def test_native_form_and_invalid_json_no_write(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}),\
             patch.object(app,'create_retained') as create:
            self.assertEqual(self.req(extra={'Content-Type':'application/x-www-form-urlencoded'})[0],400)
            self.assertEqual(self.req(body='nope')[0],400)
            create.assert_not_called()
    def test_stale_or_wrong_confirmation_fails(self):
        token=consent_qa.issue(ADMIN,action='create',now=10.0)
        body=json.dumps({'csrf':token,'confirm':'ΔΗΜΙΟΥΡΓΙΑ'},ensure_ascii=False)
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}),\
             patch.object(app,'create_retained') as create:
            self.assertEqual(self.req(body=body)[0],403)
            self.assertEqual(self.req(body=json.dumps({'csrf':consent_qa.issue(ADMIN),'confirm':'wrong'}))[0],403)
            create.assert_not_called()
    def test_probe_no_write(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}),\
             patch.object(app,'create_retained') as create,patch.object(app,'revoke_retained') as revoke:
            status,buf=self.req(path='/origin-check',body='{"probe":"metadata-v1"}',extra={'X-Smart-Pro-QA-Probe':'v1'})
            self.assertEqual(status,200)
            self.assertEqual(json.loads(buf)['code'],'request_metadata_observed_no_write')
            create.assert_not_called();revoke.assert_not_called()
    def test_unsupported_methods_denied(self):
        with patch.object(app,'create_retained') as create:
            for method in ('PUT','PATCH','DELETE'):
                self.assertEqual(self.req(method=method)[0],405)
            create.assert_not_called()
    def test_uncertain_errors_dont_claim_success(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}),\
             patch.object(app,'create_retained',side_effect=pqa.RetainedAccountError('qa_create_uncertain_inspect_users')):
            status,buf=self.req()
            self.assertEqual(status,200)
            self.assertEqual(json.loads(buf),{'code':'qa_create_uncertain_inspect_users'})
    def test_busy_lock_has_no_write(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}),\
             patch.object(app,'create_retained') as create:
            app.ROUND_TRIP_LOCK.acquire()
            try:
                status,_=self.req()
                self.assertEqual(status,409);create.assert_not_called()
            finally:app.ROUND_TRIP_LOCK.release()
