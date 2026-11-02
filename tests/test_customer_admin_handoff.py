import importlib.util
import os
import sys
import unittest
from unittest import mock
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]/'smart-pro-system'
sys.path.insert(0,str(ROOT))
import sp_customer_admin_access as m

class Request:
    def __init__(self,headers=None,peer='172.30.32.2'):
        self.client_address=(peer,5555)
        self.headers=headers or {'X-Remote-User-Id':'ABCDEFGHIJKLMNOPQRST','X-Remote-User-Groups':'system-admin'}

class TestAccess(unittest.TestCase):
    def setUp(self):
        m._approvals.clear();m._attempted.clear()
    def test_admin_core(self):
        h=Request()
        reader=lambda **kw:[{'id':'ABCDEFGHIJKLMNOPQRST','is_active':True,'group_ids':['system-admin']}]
        self.assertEqual(m.admin_identity(h,user_reader=reader,token_supplier=lambda:'x'*30),'ABCDEFGHIJKLMNOPQRST')
        with self.assertRaises(m.AccessError):m.admin_identity(Request(peer='1.1.1.1'),user_reader=reader,token_supplier=lambda:'x'*30)
        with self.assertRaises(m.AccessError):m.admin_identity(h,user_reader=lambda **kw:[],token_supplier=lambda:'x'*30)
        with self.assertRaises(m.AccessError):m.admin_identity(Request(headers={'X-Remote-User-Id':'ABCDEFGHIJKLMNOPQRST','X-Remote-User-Groups':'system-users'}),user_reader=reader,token_supplier=lambda:'x'*30)
    def test_origin(self):
        h={'Origin':'https://my-ha.local','Host':'my-ha.local','X-Smart-Pro-Admin-Action':'v1'}
        self.assertTrue(m.strict_origin(h))
        self.assertFalse(m.strict_origin({**h,'Origin':'https://evil.example'}))
        self.assertFalse(m.strict_origin({**h,'Sec-Fetch-Site':'cross-site'}))
        self.assertFalse(m.strict_origin({**h,'X-Smart-Pro-Admin-Action':'junk'}))
    def test_account_isolation(self):
        self.assertEqual(m._account_state([{'name':'Smart Pro QA LOGIN LAB','username':'smartpro_qa_login_lab'}])[0],'absent')
        u={'name':m.ACCOUNT_NAME,'username':m.ACCOUNT_USERNAME,'id':'A'*32,'credentials':[{'type':'homeassistant'}],'is_owner':False,'system_generated':False,'is_active':True,'local_only':True,'group_ids':['system-admin']}
        self.assertEqual(m._account_state([u])[0],'login_ready')
        self.assertEqual(m._account_state([{**u,'is_owner':True}])[0],'review_required')
        self.assertEqual(m._account_state([{**u,'group_ids':['system-users']}])[0],'review_required')
    def test_pair_binding(self):
        connection={'installation_id':'ID-75236','installation_token':'a'*64}
        opts={'portal_url':'https://smart-pro-system.gr','portal_basic_username':'','portal_basic_password':''}
        s=m.paired_settings(connection,opts)
        self.assertEqual(s[1],'ID-75236')
        for broken in [{'installation_id':'ID-95948','installation_token':'wrong'}, {'installation_id':'ID-!','installation_token':'a'*64}]:
            with self.assertRaises(m.AccessError):m.paired_settings(broken,opts)
        with self.assertRaises(m.AccessError):m.paired_settings(connection,{**opts,'portal_url':'http://smart-pro-system.gr'})
        with self.assertRaises(m.AccessError):m.paired_settings(connection,{**opts,'portal_url':'https://evil.example'})
    def test_preflight_does_not_write(self):
        conn={'installation_id':'ID-75236','installation_token':'a'*64}
        opts={'portal_url':'https://smart-pro-system.gr','portal_basic_username':'','portal_basic_password':''}
        wrote=[]
        def failure(_):raise m.AccessError('portal_unavailable_no_user_write')
        with self.assertRaisesRegex(m.AccessError,'portal_unavailable_no_user_write'):
            m.create_and_deliver(conn,opts,prepare=failure,create=lambda token:wrote.append(token),seal_fn=lambda p,b:b'X'*50)
        self.assertEqual(wrote,[])
    def test_preflight_fields(self):
        settings=('https://smart-pro-system.gr','ID-75236','a'*64,'','')
        from base64 import b64encode
        good={'contract':m.CONTRACT,'status':'queued','installation_id':'ID-75236','expires_at':int(__import__('time').time())+300,'request_id':'b'*32,'challenge':'c'*64,'public_key':b64encode(b'k'*32).decode()}
        self.assertEqual(m.prepare_delivery(settings,post=lambda *args:good)['installation_id'],'ID-75236')
        with self.assertRaises(m.AccessError):m.prepare_delivery(settings,post=lambda *args:{**good,'installation_id':'ID-95948'})
        with self.assertRaises(m.AccessError):m.prepare_delivery(settings,post=lambda *args:{**good,'public_key':'bad'})
    def test_one_time_consent(self):
        proof=m._issue('user-id','activate')
        self.assertFalse(m._consume('attacker','activate',proof))
        self.assertFalse(m._consume('user-id','activate',proof))
        proof=m._issue('user-id','activate')
        self.assertTrue(m._consume('user-id','activate',proof))
        self.assertFalse(m._consume('user-id','activate',proof))
    def test_portal_encryption_data_only(self):
        settings=('https://smart-pro-system.gr','ID-75236','a'*64,'','')
        info={'installation_id':'ID-75236','request_id':'a'*32,'challenge':'b'*64,'public_key':b'k'*32,'expires_at':1234567}
        sends=[]
        def transport(_settings,endpoint,payload):
            sends.append((endpoint,payload))
            return {'contract':m.CONTRACT,'status':'received'}
        def create(_):return {'username':'smartpro_managed_admin_pilot','password':'Z'*50,'id':'x'*32}
        with mock.patch.object(m,'_marker_write') as marker, mock.patch.dict(os.environ,{'SUPERVISOR_TOKEN':'s'*36}):
            result=m.create_and_deliver({}, {},post=transport,create=create,seal_fn=lambda pub,plain:b'ENCRYPTED'+bytes(max(80,len(plain))),prepared=(settings,info))
        self.assertEqual(result,'enrolled_pending_portal_receipt')
        self.assertEqual(len(sends),1)
        self.assertNotIn('Z'*50,str(sends[0][1]))
        self.assertNotIn('password',str(sends[0][1]))
        marker.assert_called_once()

if __name__=='__main__':unittest.main()
