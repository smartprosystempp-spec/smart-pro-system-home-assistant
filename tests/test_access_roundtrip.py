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
    def test_strict_origin_from_real_ingress_metadata(self):
        self.assertTrue(consent_qa.strict_origin({'Origin':'https://ha.example:8123',
            'Host':'ha.example:8123','X-Smart-Pro-QA-Action':'v1'}))
        self.assertTrue(consent_qa.strict_origin({'Origin':'https://ha.example',
            'Host':'ha.example','X-Smart-Pro-QA-Action':'v1','Sec-Fetch-Site':'same-origin'}))
    def test_cross_origin_mismatch(self):
        self.assertFalse(consent_qa.strict_origin({'Origin':'https://evil.example',
            'Host':'ha.example','X-Smart-Pro-QA-Action':'v1'}))
    def test_fetch_site_when_supplied_is_strict(self):
        for site in ('cross-site','same-site','none','other'):
            with self.subTest(site=site):
                self.assertFalse(consent_qa.strict_origin({'Origin':'https://ha.example',
                    'Host':'ha.example','X-Smart-Pro-QA-Action':'v1','Sec-Fetch-Site':site}))
    def test_duplicate_origin_or_host_denied(self):
        class Multi:
            def items(self):return [('Origin','https://ha.example'),('Origin','https://ha.example'),
                ('Host','ha.example'),('X-Smart-Pro-QA-Action','v1')]
        self.assertFalse(consent_qa.strict_origin(Multi()))
    def test_missing_action_or_origin_denied(self):
        self.assertFalse(consent_qa.strict_origin({'Origin':'https://ha.example','Host':'ha.example'}))
        self.assertFalse(consent_qa.strict_origin({'Host':'ha.example','X-Smart-Pro-QA-Action':'v1'}))
    def test_null_origin_denied(self):
        self.assertFalse(consent_qa.strict_origin({'Origin':'null','Host':'ha.example',
            'X-Smart-Pro-QA-Action':'v1'}))
    def test_browser_fetch_metadata_missing_is_allowed_with_other_proof(self):
        self.assertTrue(consent_qa.strict_origin({'Origin':'https://ha.example',
            'Host':'ha.example','X-Smart-Pro-QA-Action':'v1'}))

class HttpLiveGuardTests(unittest.TestCase):
    """Real localhost HTTP server, mocked Core authority/writer. NO live HA writes."""
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

    def request(self, method='POST', path='/account-roundtrip', extra=None, body=None,
                origin='valid'):
        urlhost=f'127.0.0.1:{self.port}'
        h={'Content-Type':'application/json',
           'X-Remote-User-Id':USER,'X-Remote-User-Groups':'system-admin',
           'X-Smart-Pro-QA-Action':'v1'}
        if origin == 'valid':h['Origin']='http://'+urlhost
        elif origin == 'invalid':h['Origin']='https://evil.example'
        if extra:h.update(extra)
        if body is None:
            body=json.dumps({'csrf':consent_qa.issue(USER),'confirm':'ΔΟΚΙΜΗ'},separators=(',',':'))
        conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=3)
        conn.request(method,path,body=body.encode('utf-8') if isinstance(body,str) else body,headers=h)
        res=conn.getresponse();data=res.read();status=res.status;headers=dict(res.getheaders())
        conn.close();return status,data,headers

    def test_actual_direct_socket_rejected_even_with_forged_headers(self):
        with patch.object(app,'run_qa_roundtrip') as writer:
            status,_,_=self.request(extra={'X-Forwarded-For':'172.30.32.2'})
            self.assertEqual(status,403)
            writer.assert_not_called()

    def test_nonadmin_denied(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':False,'reason':'non_admin'}), \
             patch.object(app,'run_qa_roundtrip') as writer:
            status,_,_=self.request()
            self.assertEqual(status,403);writer.assert_not_called()

    def test_valid_core_admin_consent_and_browser_fetch_can_write_exactly_once(self):
        token=consent_qa.issue(USER)
        payload=json.dumps({'csrf':token,'confirm':'ΔΟΚΙΜΗ'},ensure_ascii=False)
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'run_qa_roundtrip',return_value='qa_account_created_verified_deleted') as writer:
            status,body,headers=self.request(body=payload)
            self.assertEqual(status,200)
            self.assertIn('application/json',headers['Content-Type'])
            self.assertEqual(json.loads(body),{'code':'qa_account_created_verified_deleted'})
            writer.assert_called_once()
            status,_,_=self.request(body=payload)
            self.assertEqual(status,403);writer.assert_called_once()

    def test_second_distinct_token_after_first_attempt_is_denied(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'run_qa_roundtrip',return_value='qa_account_created_verified_deleted') as writer:
            status,_,_=self.request()
            self.assertEqual(status,200)
            status,_,_=self.request()
            self.assertEqual(status,409);writer.assert_called_once()

    def test_origin_mismatch_no_write(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'run_qa_roundtrip') as writer:
            status,body,_=self.request(origin='invalid')
            self.assertEqual(status,403); self.assertIn(b'origin_gate_denied_no_write',body)
            writer.assert_not_called()

    def test_cross_site_fetch_metadata_denied(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'run_qa_roundtrip') as writer:
            status,_,_=self.request(extra={'Sec-Fetch-Site':'cross-site'})
            self.assertEqual(status,403);writer.assert_not_called()

    def test_missing_origin_no_write(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'run_qa_roundtrip') as writer:
            status,_,_=self.request(origin='absent')
            self.assertEqual(status,403);writer.assert_not_called()

    def test_absent_action_header_no_write(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'run_qa_roundtrip') as writer:
            status,_,_=self.request(extra={'X-Smart-Pro-QA-Action':''})
            self.assertEqual(status,403);writer.assert_not_called()

    def test_native_html_form_no_write(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'run_qa_roundtrip') as writer:
            status,_,_=self.request(extra={'Content-Type':'application/x-www-form-urlencoded'},body='csrf=x&confirm=x')
            self.assertIn(status,(400,403));writer.assert_not_called()

    def test_missing_csrf_or_wrong_phrase_no_write(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'run_qa_roundtrip') as writer:
            status,_,_=self.request(body='{"csrf":"bad","confirm":"ΔΟΚΙΜΗ"}')
            self.assertEqual(status,403)
            status,_,_=self.request(body=json.dumps({'csrf':consent_qa.issue(USER),'confirm':'INVALID'}))
            self.assertEqual(status,403);writer.assert_not_called()

    def test_invalid_json_or_extra_fields_no_write(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'run_qa_roundtrip') as writer:
            for body in ('not json','{"csrf":1,"confirm":"ΔΟΚΙΜΗ"}',
                         '{"csrf":"abc","confirm":"ΔΟΚΙΜΗ","extra":true}',
                         'x'*513):
                with self.subTest(body=body[:20]):
                    status,_,_=self.request(body=body)
                    self.assertEqual(status,400)
            writer.assert_not_called()

    def test_unsupported_url_and_methods_denied(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'run_qa_roundtrip') as writer:
            status,_,_=self.request(path='/')
            self.assertEqual(status,405)
            for method in ('PUT','PATCH','DELETE'):
                status,_,_=self.request(method=method)
                self.assertEqual(status,405)
            writer.assert_not_called()

    def test_read_only_probe_still_works_without_sec_fetch_site(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'run_qa_roundtrip') as writer:
            status,body,_=self.request(path='/origin-check',
                 extra={'X-Smart-Pro-QA-Probe':'v1'},body='{"probe":"metadata-v1"}')
            self.assertEqual(status,200)
            result=json.loads(body)
            self.assertEqual(result['code'],'request_metadata_observed_no_write')
            self.assertEqual(result['origin'],'valid')
            self.assertEqual(result['origin_host'],'same')
            self.assertEqual(result['fetch_site'],'missing')
            self.assertEqual(result['custom_header'],'yes')
            writer.assert_not_called()

    def test_no_js_fallback_cannot_create(self):
        html=app.render_page({'is_admin':True,'reason':'ok'},consent_token='testtoken').decode()
        self.assertIn('src="probe.js"',html)
        self.assertIn('action="account-roundtrip"',html)
        self.assertNotIn(USER,html)
        self.assertIn('ΔΟΚΙΜΗ',html)
        js=(ROOT/'smart-pro-access-preflight/probe.js').read_text()
        self.assertIn("mode: 'same-origin'",js)
        self.assertIn('event.preventDefault()',js)
        self.assertIn('X-Smart-Pro-QA-Action',js)
        self.assertNotIn('config/auth/create',js)

    def test_uncertain_writer_result_not_misreported_as_success(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'run_qa_roundtrip',side_effect=qa.RoundTripError('cleanup_uncertain_check_users')):
            status,body,_=self.request()
            self.assertEqual(status,200)
            self.assertEqual(json.loads(body),{'code':'cleanup_uncertain_check_users'})

    def test_busy_action_does_not_write(self):
        with patch.object(app,'verify_live_core_admin',return_value={'is_admin':True,'reason':'ok'}), \
             patch.object(app,'run_qa_roundtrip') as writer:
            app.ROUND_TRIP_LOCK.acquire()
            try:
                status,_,_=self.request()
                self.assertEqual(status,409); writer.assert_not_called()
            finally: app.ROUND_TRIP_LOCK.release()

    def test_qa_docker_includes_only_expected_writer_module(self):
        d=(ROOT/'smart-pro-access-preflight/Dockerfile').read_text()
        self.assertIn('COPY account_roundtrip.py',d)
        self.assertIn('COPY consent_qa.py',d)
        self.assertIn('COPY probe.js',d)
        self.assertNotIn('COPY smart-pro-system',d)

    def test_no_nonadmin_forms(self):
        html=app.render_page({'is_admin':False,'reason':'non_admin'}).decode()
        self.assertNotIn('account-roundtrip-form',html)
        self.assertNotIn('origin-probe-form',html)

if __name__=='__main__':unittest.main()
