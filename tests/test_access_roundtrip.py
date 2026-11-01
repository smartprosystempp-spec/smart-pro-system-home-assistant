"""QA 0.3.0: consent, fixed Core command allow-list, create+revoke rollback.
No real Home Assistant operations are performed in this test module.
"""
import http.client
import pathlib
import sys
import threading
import unittest
import urllib.parse
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'smart-pro-access-preflight'))
import app
import consent_qa
import account_roundtrip as qa

USER = '0123456789abcdef0123456789abcdef'

class MockCore:
    def __init__(self, token='TOKEN_TEST', *, fail_at=None, preexisting=False, mutation=None):
        self.token = token
        self.fail_at = fail_at
        self.preexisting = preexisting
        self.mutation = mutation
        self.users = [{'id':USER,'name':'Real admin','is_owner':True,'is_active':True,'system_generated':False,'group_ids':['system-admin'],'credentials':[], 'local_only':False}]
        if preexisting:
            self.users.append(dict(self.users[0],name=qa.NAME_PREFIX+'bbbbbbbbbbbb',id='c'*32))
        self.invocations = []
    def __enter__(self): return self
    def __exit__(self,*_): pass
    def command(self, command_type, **params):
        self.invocations.append((command_type,params))
        if command_type == self.fail_at:
            raise qa.RoundTripError('simulated_error')
        if command_type=='config/auth/list': return list(self.users)
        if command_type=='config/auth/create':
            user=dict(id='f'*32,name=params['name'],is_owner=False,is_active=True,system_generated=False,local_only=True,group_ids=params['group_ids'],credentials=[])
            if self.mutation: user.update(self.mutation)
            self.users.append(user)
            return {'user':user}
        if command_type=='config/auth/delete':
            self.users=[u for u in self.users if u['id']!=params['user_id']]
            return {}
        raise AssertionError('unknown cmd')

class RoundtripTests(unittest.TestCase):
    def run_ok(self, *, fake=None):
        fake=fake or MockCore()
        output=qa.run_qa_roundtrip(supervisor_token='x'*50,session_factory=lambda _:fake,suffix_supplier=lambda:'abcdef012345')
        return output,fake
    def test_success_created_deleted(self):
        code,f=self.run_ok()
        self.assertEqual(code,'qa_account_created_verified_deleted')
        self.assertEqual([cmd for cmd,_ in f.invocations],['config/auth/list','config/auth/create','config/auth/list','config/auth/delete','config/auth/list'])
        self.assertEqual(len(f.users),1)
    def test_admin_nonowner_and_local_only(self):
        _,f=self.run_ok()
        create=f.invocations[1][1]
        self.assertEqual(create['group_ids'],['system-admin'])
        self.assertTrue(create['local_only'])
        self.assertTrue(create['name'].startswith(qa.NAME_PREFIX))
        self.assertEqual(set(create.keys()),{'name','group_ids','local_only'})
    def test_no_username_password_or_portal(self):
        _,f=self.run_ok()
        self.assertNotIn('password',str(f.invocations).lower())
        self.assertNotIn('username',str(f.invocations).lower())
        self.assertNotIn('portal',str(f.invocations).lower())
    def test_existing_qa_name_blocks_duplicate(self):
        f=MockCore(preexisting=True)
        with self.assertRaisesRegex(qa.RoundTripError,'existing_qa_account_stop'):
            self.run_ok(fake=f)
        self.assertEqual([x[0] for x in f.invocations],['config/auth/list'])
    def test_invalid_suffix_is_blocked(self):
        with self.assertRaisesRegex(qa.RoundTripError,'qa_suffix_invalid'):
            qa.run_qa_roundtrip(supervisor_token='x'*50,suffix_supplier=lambda:'TRAVERSAL')
    def test_core_create_failure_does_not_issue_delete(self):
        f=MockCore(fail_at='config/auth/create')
        with self.assertRaisesRegex(qa.RoundTripError,'simulated_error'):
            self.run_ok(fake=f)
        self.assertEqual([x[0] for x in f.invocations],['config/auth/list','config/auth/create'])
    def test_delete_failure_is_fail_closed(self):
        f=MockCore(fail_at='config/auth/delete')
        with self.assertRaisesRegex(qa.RoundTripError,'cleanup_uncertain_check_users'):
            self.run_ok(fake=f)
        self.assertEqual(len(f.users),2)
    def test_wrong_group_triggers_cleanup(self):
        f=MockCore(mutation={'group_ids':['system-users']})
        with self.assertRaisesRegex(qa.RoundTripError,'created_user_permissions_mismatch'):
            self.run_ok(fake=f)
        self.assertEqual(len(f.users),1)
        self.assertEqual(f.invocations[-1][0],'config/auth/delete')
    def test_credentials_attached_triggers_cleanup(self):
        f=MockCore(mutation={'credentials':[{'type':'homeassistant'}]})
        with self.assertRaisesRegex(qa.RoundTripError,'unexpected_credentials_attached'):
            self.run_ok(fake=f)
        self.assertEqual(len(f.users),1)
    def test_owner_flag_triggers_cleanup(self):
        f=MockCore(mutation={'is_owner':True})
        with self.assertRaisesRegex(qa.RoundTripError,'created_user_permissions_mismatch'):
            self.run_ok(fake=f)
        self.assertEqual(len(f.users),1)
    def test_no_non_allowlisted_commands(self):
        with self.assertRaisesRegex(qa.RoundTripError,'command_not_allowed'):
            qa.SupervisorCoreSession('x'*40).command('config/auth_provider/homeassistant/create',username='bad',password='bad')
    def test_invalid_inventory_denied_before_creation(self):
        f=MockCore()
        f.users=[]
        with self.assertRaisesRegex(qa.RoundTripError,'inventory_invalid'):
            self.run_ok(fake=f)
    def test_preexisting_does_not_create(self):
        f=MockCore(preexisting=True)
        with self.assertRaises(qa.RoundTripError):self.run_ok(fake=f)
        self.assertFalse(any(x[0]=='config/auth/create' for x in f.invocations))

class ConsentTests(unittest.TestCase):
    def setUp(self):
        with consent_qa._lock:
            consent_qa._issued.clear()
            consent_qa._attempted=False
    def test_one_time(self):
        token=consent_qa.issue(USER,now=100.0)
        self.assertTrue(consent_qa.consume(token,USER,'ΔΟΚΙΜΗ',now=101.0))
        self.assertFalse(consent_qa.consume(token,USER,'ΔΟΚΙΜΗ',now=101.0))
    def test_expired(self):
        token=consent_qa.issue(USER,now=100.0)
        self.assertFalse(consent_qa.consume(token,USER,'ΔΟΚΙΜΗ',now=281.0))
    def test_other_user(self):
        token=consent_qa.issue(USER,now=100.0)
        self.assertFalse(consent_qa.consume(token,'a'*32,'ΔΟΚΙΜΗ',now=101.0))
    def test_wrong_phrase(self):
        token=consent_qa.issue(USER,now=100.0)
        self.assertFalse(consent_qa.consume(token,USER,'δοκιμή',now=101.0))
        self.assertFalse(consent_qa.consume(token,USER,'ΔΟΚΙΜΗ',now=102.0))
    def test_refresh_invalidates_old(self):
        t1=consent_qa.issue(USER,now=100.0)
        t2=consent_qa.issue(USER,now=120.0)
        self.assertFalse(consent_qa.consume(t1,USER,'ΔΟΚΙΜΗ',now=121.0))
        self.assertTrue(consent_qa.consume(t2,USER,'ΔΟΚΙΜΗ',now=121.0))
    def test_once_per_process(self):
        self.assertTrue(consent_qa.allow_one_attempt())
        self.assertFalse(consent_qa.allow_one_attempt())
    def test_origin(self):
        self.assertTrue(consent_qa.same_origin({'Origin':'https://ha.example:8123','Host':'ha.example:8123'}))
        self.assertFalse(consent_qa.same_origin({'Origin':'https://evil.example','Host':'ha.example'}))
        self.assertFalse(consent_qa.same_origin({'Host':'ha.example'}))
        self.assertFalse(consent_qa.same_origin({'Origin':'null','Host':'ha.example'}))

class HttpLiveGuardTests(unittest.TestCase):
    """Exercise actual HTTP app server, using locally mocked authenticated Core users."""
    @classmethod
    def setUpClass(cls):
        cls.server=app.Server(('127.0.0.1',0),app.Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.port=cls.server.server_port
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(5)
    def setUp(self):
        with consent_qa._lock:
            consent_qa._issued.clear(); consent_qa._attempted=False
    def post(self,body='csrf=x&confirm=%CE%94%CE%9F%CE%9A%CE%99%CE%9C%CE%97',extra=None):
        h={'Origin':f'http://127.0.0.1:{self.port}','Content-Type':'application/x-www-form-urlencoded',
           'X-Remote-User-Id':USER,'X-Remote-User-Groups':'system-admin'}
        if extra: h.update(extra)
        conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=3)
        conn.request('POST','/',body=body,headers=h)
        res=conn.getresponse();data=res.read();status=res.status;conn.close();return status,data
    def test_direct_http_post_is_denied_no_action(self):
        with patch.object(app,'run_qa_roundtrip') as action:
            status,_=self.post();self.assertEqual(status,403); action.assert_not_called()
    def test_forged_x_forwarded_for_does_not_help(self):
        with patch.object(app,'run_qa_roundtrip') as action:
            status,_=self.post(extra={'X-Forwarded-For':'172.30.32.2'})
            self.assertEqual(status,403);action.assert_not_called()
    def test_nonadmin_denied_even_if_peer_mocked(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':False,'reason':'non_admin'}),patch.object(app,'run_qa_roundtrip') as action:
            status,_=self.post();self.assertEqual(status,403); action.assert_not_called()
    def test_admin_requires_real_consent(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'verified'}),patch.object(app,'run_qa_roundtrip') as action:
            status,_=self.post();self.assertEqual(status,403);action.assert_not_called()
    def test_valid_once_admin_write(self):
        token=consent_qa.issue(USER)
        body=urllib.parse.urlencode({'csrf':token,'confirm':'ΔΟΚΙΜΗ'})
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'verified'}),patch.object(app,'run_qa_roundtrip',return_value='qa_account_created_verified_deleted') as action:
            status,raw=self.post(body)
            self.assertEqual(status,200);self.assertIn(b'qa_account_created_verified_deleted',raw)
            self.assertEqual(action.call_count,1)
            replay,_=self.post(body)
            self.assertEqual(replay,403)
            self.assertEqual(action.call_count,1)
    def test_invalid_origin_denied(self):
        token=consent_qa.issue(USER)
        body=urllib.parse.urlencode({'csrf':token,'confirm':'ΔΟΚΙΜΗ'})
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'verified'}),patch.object(app,'run_qa_roundtrip') as action:
            status,_=self.post(body,{'Origin':'https://external.invalid'})
            self.assertEqual(status,403);action.assert_not_called()
    def test_wrong_identity_denied(self):
        token=consent_qa.issue('a'*32)
        body=urllib.parse.urlencode({'csrf':token,'confirm':'ΔΟΚΙΜΗ'})
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'verified'}),patch.object(app,'run_qa_roundtrip') as action:
            status,_=self.post(body)
            self.assertEqual(status,403);action.assert_not_called()
    def test_no_personal_identity_in_form(self):
        html=app.render_page({'is_admin':True,'reason':'verified'},'TEST_TOKEN').decode()
        self.assertNotIn(USER,html)
        self.assertNotIn('SUPERVISOR_TOKEN',html)
        self.assertIn('ΔΟΚΙΜΗ',html)
        self.assertIn('TEST_TOKEN',html)

if __name__=='__main__':unittest.main()
