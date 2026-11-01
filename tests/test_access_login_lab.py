"""Isolated credential-lab tests, fake HA Core + real local socket HTTP.

No real passwords from any user, no HA server and no network beyond localhost.
"""
from __future__ import annotations
import http.client, json, pathlib, sys, threading, unittest
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'smart-pro-access-preflight'))
import app, consent_qa
import credential_lab_qa as lab
from core_session_qa import RoundTripError

ADMIN='a'*32
SECRET='S'*54

def owner():
    return dict(id=ADMIN,name='Home Assistant Owner',username='owner',is_active=True,
                is_owner=True,system_generated=False,local_only=False,
                group_ids=['system-admin'],credentials=[{'type':'homeassistant'}])

def qa(*, login=False):
    return dict(id='b'*32,name=lab.LAB_NAME,username=lab.LAB_USERNAME if login else None,
                is_active=True,is_owner=False,system_generated=False,local_only=True,
                group_ids=['system-admin'],credentials=[{'type':'homeassistant'}] if login else [])

class FakeCore:
    def __init__(self,users=None):
        self.users=list(users) if users is not None else [owner()]
        self.calls=[]
        self.fail=None
        self.created_credential=None
    def __enter__(self):return self
    def __exit__(self,*_):return False
    def command(self,cmd,**params):
        self.calls.append((cmd,params))
        if cmd==self.fail:raise RoundTripError('simulated_core_failure')
        if cmd=='config/auth/list':return [dict(u) for u in self.users]
        if cmd=='config/auth/create':
            u=qa()
            self.users.append(u)
            return {'user':dict(u)}
        if cmd=='config/auth_provider/homeassistant/create':
            assert params['user_id']=='b'*32
            self.created_credential=params['password']
            self.users[-1]['credentials']=[{'type':'homeassistant'}]
            self.users[-1]['username']=params['username']
            return None
        if cmd=='config/auth/delete':
            assert params['user_id']=='b'*32
            self.users=[u for u in self.users if u['id']!='b'*32]
            self.created_credential=None
            return None
        raise AssertionError(cmd)

class CredentialLifecycle(unittest.TestCase):
    def test_allowlist_enables_exact_provider_create_not_arbitrary_commands(self):
        from core_session_qa import SupervisorCoreSession
        self.assertEqual(SupervisorCoreSession.ALLOWED,{"config/auth/list","config/auth/create","config/auth/delete","config/auth_provider/homeassistant/create"})

    def test_absent_and_creation_with_real_credentials(self):
        f=FakeCore()
        self.assertEqual(lab.inspect_lab(supervisor_token='x'*40,session_factory=lambda _:f),'absent')
        data=lab.create_lab(supervisor_token='x'*40,session_factory=lambda _:f,password_factory=lambda:SECRET)
        self.assertEqual(data['code'],'qa_login_admin_created_credentials_linked')
        self.assertEqual(data['username'],lab.LAB_USERNAME)
        self.assertEqual(data['password'],SECRET)
        self.assertEqual(f.created_credential,SECRET)
        self.assertEqual(lab.inspect_lab(supervisor_token='x'*40,session_factory=lambda _:f),'login_ready')
        self.assertEqual([x[0] for x in f.calls],['config/auth/list','config/auth/list','config/auth/create','config/auth/list','config/auth_provider/homeassistant/create','config/auth/list','config/auth/list'])
    def test_cryptographically_random_password(self):
        f=FakeCore()
        data=lab.create_lab(supervisor_token='x'*40,session_factory=lambda _:f)
        self.assertGreaterEqual(len(data['password']),40)
        self.assertNotEqual(data['password'],SECRET)
        self.assertNotIn(data['password'],str(f.users))
    def test_no_second_creation(self):
        f=FakeCore([owner(),qa(login=True)])
        with self.assertRaisesRegex(lab.LabCredentialError,'existing_account'):
            lab.create_lab(supervisor_token='x'*40,session_factory=lambda _:f)
        self.assertFalse(any(cmd=='config/auth/create' for cmd,_ in f.calls))
    def test_existing_name_no_credentials_blocks(self):
        f=FakeCore([owner(),qa()])
        self.assertEqual(lab.inspect_lab(supervisor_token='x'*40,session_factory=lambda _:f),'incomplete_no_login')
        with self.assertRaises(lab.LabCredentialError):
            lab.create_lab(supervisor_token='x'*40,session_factory=lambda _:f)
    def test_username_collision_blocks(self):
        u=dict(owner(),id='c'*32,username=lab.LAB_USERNAME)
        f=FakeCore([owner(),u])
        self.assertEqual(lab.inspect_lab(supervisor_token='x'*40,session_factory=lambda _:f),'review_required')
        with self.assertRaises(lab.LabCredentialError):lab.create_lab(supervisor_token='x'*40,session_factory=lambda _:f)
    def test_bad_random_password_blocks_before_writes(self):
        f=FakeCore()
        with self.assertRaisesRegex(lab.LabCredentialError,'password_invalid'):
            lab.create_lab(supervisor_token='x'*40,session_factory=lambda _:f,password_factory=lambda:'abc')
        self.assertFalse(any(cmd=='config/auth/create' for cmd,_ in f.calls))
    def test_credential_provider_failure_leaves_no_login_and_requires_revoke(self):
        f=FakeCore();f.fail='config/auth_provider/homeassistant/create'
        with self.assertRaisesRegex(lab.LabCredentialError,'uncertain_inspect_users'):
            lab.create_lab(supervisor_token='x'*40,session_factory=lambda _:f,password_factory=lambda:SECRET)
        self.assertEqual(lab.inspect_lab(supervisor_token='x'*40,session_factory=lambda _:f),'incomplete_no_login')
    def test_manual_revoke_of_completed_login(self):
        f=FakeCore([owner(),qa(login=True)])
        self.assertEqual(lab.revoke_lab(supervisor_token='x'*40,session_factory=lambda _:f),'qa_login_admin_revoked_verified')
        self.assertEqual(lab.inspect_lab(supervisor_token='x'*40,session_factory=lambda _:f),'absent')
        self.assertEqual(len(f.users),1)
        self.assertEqual(f.calls[1][0],'config/auth/delete')
    def test_revoke_incomplete_account(self):
        f=FakeCore([owner(),qa()]);self.assertEqual(lab.revoke_lab(supervisor_token='x'*40,session_factory=lambda _:f),'qa_login_admin_revoked_verified')
    def test_revoke_absent_no_writes(self):
        f=FakeCore()
        self.assertEqual(lab.revoke_lab(supervisor_token='x'*40,session_factory=lambda _:f),'qa_login_admin_already_absent')
        self.assertFalse(any(cmd=='config/auth/delete' for cmd,_ in f.calls))
    def test_revoke_denies_altered_account(self):
        for flags in ({'is_owner':True},{'local_only':False},{'is_active':False},{'system_generated':True},
                      {'group_ids':['system-users']},{'credentials':[{'type':'other'}]},
                      {'username':'different'},{'name':lab.LAB_NAME+' OTHER'}):
            with self.subTest(flags=flags):
                f=FakeCore([owner(),dict(qa(login=True),**flags)])
                with self.assertRaises(lab.LabCredentialError):
                    lab.revoke_lab(supervisor_token='x'*40,session_factory=lambda _:f)
                self.assertFalse(any(cmd=='config/auth/delete' for cmd,_ in f.calls))
    def test_duplicate_names_denied(self):
        f=FakeCore([owner(),qa(login=True),dict(qa(),id='c'*32)])
        self.assertEqual(lab.inspect_lab(supervisor_token='x'*40,session_factory=lambda _:f),'review_required')
        with self.assertRaises(lab.LabCredentialError):lab.revoke_lab(supervisor_token='x'*40,session_factory=lambda _:f)
    def test_failed_revoke_never_claims_success(self):
        f=FakeCore([owner(),qa(login=True)]);f.fail='config/auth/delete'
        with self.assertRaisesRegex(lab.LabCredentialError,'revoke_uncertain'):
            lab.revoke_lab(supervisor_token='x'*40,session_factory=lambda _:f)
        self.assertEqual(len(f.users),2)
    def test_safe_view_only_renders_no_secret_or_form_to_normal_user(self):
        html=app.render_page({'is_admin':False,'reason':'non_admin'},lab_state='absent',lab_create_token='S').decode()
        self.assertNotIn('lab-login-create-form',html)
        self.assertNotIn(SECRET,html)
    def test_only_absent_has_create_and_only_ready_has_revoke(self):
        ok={'is_admin':True,'reason':'ok'}
        h=app.render_page(ok,lab_state='absent',lab_create_token='a').decode()
        self.assertIn('lab-login-create-form',h);self.assertNotIn('lab-login-revoke-form',h)
        h=app.render_page(ok,lab_state='login_ready',lab_revoke_token='b').decode()
        self.assertIn('lab-login-revoke-form',h);self.assertNotIn('lab-login-create-form',h)
        h=app.render_page(ok,lab_state='review_required',lab_create_token='a',lab_revoke_token='b').decode()
        self.assertNotIn('lab-login-revoke-form',h);self.assertNotIn('lab-login-create-form',h)
    def test_consent_scopes_are_independent(self):
        with consent_qa._lock:consent_qa._issued.clear();consent_qa._attempted=set()
        create=consent_qa.issue(ADMIN,action='lab_create')
        revoke=consent_qa.issue(ADMIN,action='lab_revoke')
        self.assertFalse(consent_qa.consume(create,ADMIN,'ΣΥΝΔΕΣΗ',action='lab_revoke'))
        self.assertTrue(consent_qa.consume(revoke,ADMIN,'ΔΙΑΓΡΑΦΗ',action='lab_revoke'))
        self.assertFalse(consent_qa.consume(revoke,ADMIN,'ΔΙΑΓΡΑΦΗ',action='lab_revoke'))

class LabHttp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=app.Server(('127.0.0.1',0),app.Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start();cls.port=cls.server.server_port
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(5)
    def setUp(self):
        with consent_qa._lock:consent_qa._issued.clear();consent_qa._attempted=set()
    def request(self,path='/lab-login-create',*,admin=True,csrf=True,origin='good',action_header='v1',scope='lab_create',confirm=None):
        h={'Content-Type':'application/json','X-Remote-User-Id':ADMIN,'X-Smart-Pro-QA-Action':action_header}
        if origin=='good':h['Origin']=f'http://127.0.0.1:{self.port}'
        elif origin=='bad':h['Origin']='https://wrong.example'
        if csrf: token=consent_qa.issue(ADMIN,action=scope)
        else: token='forged'
        if confirm is None:confirm='ΣΥΝΔΕΣΗ' if scope=='lab_create' else 'ΔΙΑΓΡΑΦΗ'
        conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=5)
        conn.request('POST',path,json.dumps({'csrf':token,'confirm':confirm}).encode(),h)
        res=conn.getresponse();data=res.read();status=res.status;conn.close()
        return status,data
    def test_external_network_headers_do_not_create(self):
        with patch.object(app,'create_lab') as write:
            status,_=self.request()
            self.assertEqual(status,403);write.assert_not_called()
    def test_admin_can_create_once_with_secret_response(self):
        result={'code':'qa_login_admin_created_credentials_linked','username':lab.LAB_USERNAME,'password':SECRET}
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}),\
             patch.object(app,'create_lab',return_value=result) as write:
            status,data=self.request();self.assertEqual(status,200)
            self.assertEqual(json.loads(data),result)
            self.assertEqual(write.call_count,1)
            status,_=self.request();self.assertEqual(status,409);self.assertEqual(write.call_count,1)
    def test_no_create_for_nonnadmin(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':False,'reason':'non_admin'}),\
             patch.object(app,'create_lab') as write:
            status,_=self.request();self.assertEqual(status,403);write.assert_not_called()
    def test_cross_site_denied(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}),\
             patch.object(app,'create_lab') as write:
            self.assertEqual(self.request(origin='bad')[0],403)
            self.assertEqual(self.request(action_header='')[0],403)
            write.assert_not_called()
    def test_invalid_csrf_or_word_denied(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}),\
             patch.object(app,'create_lab') as write:
            self.assertEqual(self.request(csrf=False)[0],403)
            self.assertEqual(self.request(confirm='wrong')[0],403)
            write.assert_not_called()
    def test_lab_create_token_not_valid_for_revoke(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}),\
             patch.object(app,'revoke_lab') as write:
            self.assertEqual(self.request('/lab-login-revoke',scope='lab_create')[0],403)
            write.assert_not_called()
    def test_lab_revoke_with_own_approval(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}),\
             patch.object(app,'revoke_lab',return_value='qa_login_admin_revoked_verified') as revoke:
            status,data=self.request('/lab-login-revoke',scope='lab_revoke')
            self.assertEqual(status,200);self.assertEqual(json.loads(data)['code'],'qa_login_admin_revoked_verified')
            revoke.assert_called_once()
    def test_error_does_not_expose_password(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}),\
             patch.object(app,'create_lab',side_effect=lab.LabCredentialError('qa_login_write_uncertain_inspect_users')):
            status,data=self.request();self.assertEqual(status,200)
            self.assertNotIn(b'password',data)
            self.assertEqual(json.loads(data)['code'],'qa_login_write_uncertain_inspect_users')

if __name__=='__main__':unittest.main()
