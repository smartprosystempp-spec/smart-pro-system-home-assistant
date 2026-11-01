"""QA 0.3.0: consent, fixed Core command allow-list, create+revoke rollback.
No real Home Assistant operations are performed in this test module.
"""
import http.client
import json
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
        self.assertTrue(consent_qa.same_origin({'Origin':'https://ha.example:8123','Host':'supervisor:8107','Sec-Fetch-Site':'same-origin'}))
        self.assertFalse(consent_qa.same_origin({'Origin':'https://evil.example','Host':'ha.example','Sec-Fetch-Site':'cross-site'}))
        self.assertFalse(consent_qa.same_origin({'Origin':'https://evil.example','Host':'ha.example','Sec-Fetch-Site':'same-site'}))
        self.assertFalse(consent_qa.same_origin({'Origin':'https://ha.example','Host':'supervisor:8107','Sec-Fetch-Site':'none'}))
        self.assertFalse(consent_qa.same_origin({'Origin':'null','Host':'supervisor:8107','Sec-Fetch-Site':'same-origin'}))
        self.assertFalse(consent_qa.same_origin({'Host':'supervisor:8107','Sec-Fetch-Site':'same-origin'}))
        self.assertFalse(consent_qa.same_origin({'Origin':'https://ha.example','Host':'supervisor:8107'}))

class HttpLiveGuardTests(unittest.TestCase):
    """All actual HTTP routes are strictly no-write in 0.3.2."""
    @classmethod
    def setUpClass(cls):
        cls.server=app.Server(('127.0.0.1',0),app.Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.port=cls.server.server_port
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(5)

    def request(self, method='POST', path='/origin-check', extra=None, body=''):
        h={'Origin':'https://ha.example','Content-Type':'application/x-www-form-urlencoded',
           'X-Remote-User-Id':USER,'X-Remote-User-Groups':'system-admin'}
        if extra: h.update(extra)
        conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=3)
        conn.request(method,path,body=body,headers=h)
        res=conn.getresponse();data=res.read();headers=res.getheaders();status=res.status
        conn.close();return status,data,dict(headers)

    def test_no_writer_imported(self):
        self.assertFalse(hasattr(app,'run_qa_roundtrip'))
        self.assertNotIn('account_roundtrip',app.__dict__)
        self.assertNotIn('consent_qa',app.__dict__)

    def test_privileged_write_request_permanently_disabled(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'verified'}):
            for method in ('POST','PUT','PATCH','DELETE'):
                with self.subTest(method=method):
                    status,body,_=self.request(method=method,path='/')
                    self.assertEqual(status,405)
                    self.assertEqual(body,b'NO USER WRITES')

    def test_direct_unauthenticated_probe_denied(self):
        status,body,_=self.request(path='/origin-check')
        self.assertEqual(status,403)
        self.assertIn(b'Administrator required',body)

    def test_nonadmin_probe_denied(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':False,'reason':'non_admin'}):
            status,body,_=self.request(path='/origin-check')
            self.assertEqual(status,403)
            self.assertIn(b'Administrator required',body)

    def test_real_local_http_probe_responds_only_sanitized_categories(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'verified'}):
            status,body,_=self.request(extra={'Sec-Fetch-Site':'same-origin',
                'X-Smart-Pro-QA-Probe':'v1','Content-Type':'application/json'},body='{"probe":"metadata-v1"}')
            self.assertEqual(status,200)
            response=json.loads(body)
            self.assertEqual(response['code'],'request_metadata_observed_no_write')
            self.assertEqual(response['origin'],'valid')
            self.assertEqual(response['fetch_site'],'same-origin')
            self.assertEqual(response['custom_header'],'yes')
            self.assertNotIn(b'https://ha.example',body)
            self.assertNotIn(USER.encode(),body)

    def test_html_form_fallback_is_read_only(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'verified'}):
            status,body,_=self.request()
            self.assertEqual(status,200)
            self.assertIn(b'request_metadata_observed_no_write',body)
            self.assertNotIn(b'config/auth/create',body)

    def test_nobody_can_post_account_creation_even_with_forged_headers(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'verified'}):
            status,body,_=self.request(path='/',extra={'Sec-Fetch-Site':'same-origin',
              'X-Smart-Pro-QA-Probe':'v1','X-Forwarded-For':'172.30.32.2'},
              body='csrf=fake&confirm=somevalue')
            self.assertEqual(status,405)
            self.assertEqual(body,b'NO USER WRITES')

    def test_get_script_denied_untrusted_peer(self):
        status,body,_=self.request(method='GET',path='/probe.js')
        self.assertEqual(status,403)
        self.assertEqual(body,b'Forbidden')

    def test_no_side_effect_on_malformed_post(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'verified'}):
            status,_,_=self.request(path='/origin-check',body='x'*257)
            self.assertEqual(status,400)

    def test_safe_same_origin_script_is_local_and_bounded(self):
        self.assertLess(len(app.SCRIPT_BYTES),12000)
        self.assertIn(b'X-Smart-Pro-QA-Probe',app.SCRIPT_BYTES)
        self.assertNotIn(b'config/auth/create',app.SCRIPT_BYTES)
        html=app.render_page({'is_admin':True,'reason':'verified'}).decode()
        self.assertIn('src="probe.js"',html)
        self.assertNotIn('Έγκριση ελεγχόμενης δοκιμής',html)

    def test_weak_meta_cannot_turn_into_authority(self):
        s=app.classify_request_metadata({'Origin':'null','Host':'supervisor',
             'Sec-Fetch-Site':'cross-site','X-Smart-Pro-QA-Probe':'v1'})
        self.assertEqual(s['origin'],'null')
        self.assertEqual(s['fetch_site'],'cross-site')
        self.assertEqual(s['origin_host'],'unknown')
        self.assertNotIn('is_admin',s)

    def test_nonadmin_page_has_no_form(self):
        html=app.render_page({'is_admin':False,'reason':'non_admin'}).decode()
        self.assertNotIn('origin-probe-form',html)

    def test_duplicate_and_unexpected_headers_are_classified(self):
        class Multi:
            def items(self):
                return [('Origin','https://a.example'),('Origin','https://b.example'),
                        ('Host','supervisor'),('Sec-Fetch-Site','custom-value')]
        result=app.classify_request_metadata(Multi())
        self.assertEqual(result['origin'],'missing')
        self.assertEqual(result['fetch_site'],'other')

    def test_docker_excludes_qa_account_writer(self):
        image=(ROOT/'smart-pro-access-preflight'/'Dockerfile').read_text()
        self.assertNotIn('COPY account_roundtrip.py',image)
        self.assertNotIn('COPY consent_qa.py',image)
        self.assertIn('COPY probe.js',image)


if __name__=='__main__':unittest.main()
