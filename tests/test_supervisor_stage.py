"""Offline Supervisor staging tests. Does not use network, real tokens or backups."""
import hashlib
import hmac
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'smart-pro-system'))
import recovery_stage as m


def archive_at(path, metadata=None, unsafe=None):
    if metadata is None:
        metadata={'slug':'deadbeef','type':'full','name':'Offline QA'}
    with tarfile.open(path,'w:') as tar:
        raw=json.dumps(metadata).encode()
        tarinfo=tarfile.TarInfo('./backup.json');tarinfo.size=len(raw)
        tar.addfile(tarinfo,io.BytesIO(raw))
        if unsafe:
            bad=tarfile.TarInfo(unsafe);bad.size=2
            tar.addfile(bad,io.BytesIO(b'xx'))
        other=tarfile.TarInfo('./homeassistant.tar.gz');other.size=3
        tar.addfile(other,io.BytesIO(b'abc'))
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    return path.stat().st_size,digest


class StageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.archive=self.root/'artifact.tar'
        self.size,self.sha=archive_at(self.archive)

    def test_valid_archive_metadata(self):
        self.assertEqual(m._validated_archive(self.archive,self.size,self.sha),'deadbeef')

    def test_sha_mismatch(self):
        with self.assertRaisesRegex(ValueError,'sha256'):
            m._validated_archive(self.archive,self.size,'0'*64)

    def test_size_mismatch(self):
        with self.assertRaisesRegex(ValueError,'file_invalid'):
            m._validated_archive(self.archive,self.size+1,self.sha)

    def test_symlink_refused(self):
        link=self.root/'link.tar';link.symlink_to(self.archive)
        with self.assertRaisesRegex(ValueError,'file_invalid'):
            m._validated_archive(link,self.size,self.sha)

    def test_unsafe_archive_member_refused(self):
        s,h=archive_at(self.archive,unsafe='../danger.txt')
        with self.assertRaisesRegex(ValueError,'unsafe_member'):
            m._validated_archive(self.archive,s,h)

    def test_invalid_backup_metadata_refused(self):
        s,h=archive_at(self.archive,metadata={'slug':'deadbeef','type':'invalid'})
        with self.assertRaisesRegex(ValueError,'metadata_invalid'):
            m._validated_archive(self.archive,s,h)

    def test_encrypted_inner_archive_is_not_unpacked(self):
        self.assertEqual(m._validated_archive(self.archive,self.size,self.sha),'deadbeef')

    def _signed_request(self):
        now=int(time.time())
        req={'contract':'smart-pro-managed-backup-supervisor-stage-v1','action':'stage_verified_archive_only',
             'request_id':'mbst_'+'a'*32,'installation_id':'ID-TEST','node_id':'b'*64,
             'point_id':'mbrp_'+'c'*32,'recovery_request_id':'mbr_'+'d'*32,
             'object_sha256':self.sha,'object_size':self.size,'case_id':'mbhr_'+'e'*32,
             'nonce':'f'*32,'issued_at':now,'expires_at':now+120,
             'supervisor_upload_authorized':True,'restore_authorized':False,
             'delete_authorized':False,'export_authorized':False}
        self._sign(req);return req

    @staticmethod
    def _sign(req):
        data={k:v for k,v in req.items() if k!='signature'}
        body=json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        req['signature']=hmac.new(b'x'*32,body,hashlib.sha256).hexdigest()

    def _ctx(self):return {'installation_id':'ID-TEST','node_id':'b'*64,'secret':b'x'*32}

    def _verified(self):
        return {'state':'verified','reason':'full_sha256_verified',
                'request_id':'mbr_'+'d'*32,'point_id':'mbrp_'+'c'*32,
                'node_id':'b'*64,'sha256':self.sha,'bytes_received':self.size}

    def test_valid_signed_exact_archive_request(self):
        with patch.object(m.recovery_verifier,'public_result',return_value=self._verified()):
            self.assertIsNotNone(m._validate(self._signed_request(),self._ctx()))

    def test_tampered_signature_rejected(self):
        r=self._signed_request();r['object_size']+=1
        with patch.object(m.recovery_verifier,'public_result',return_value=self._verified()):
            self.assertIsNone(m._validate(r,self._ctx()))

    def test_old_or_expired_request_rejected(self):
        r=self._signed_request();r['expires_at']=int(time.time())-1;self._sign(r)
        with patch.object(m.recovery_verifier,'public_result',return_value=self._verified()):
            self.assertIsNone(m._validate(r,self._ctx()))

    def test_wrong_node_refused(self):
        r=self._signed_request();r['node_id']='c'*64;self._sign(r)
        with patch.object(m.recovery_verifier,'public_result',return_value=self._verified()):
            self.assertIsNone(m._validate(r,self._ctx()))

    def test_restore_delete_export_must_stay_false(self):
        for field in ('restore_authorized','delete_authorized','export_authorized'):
            r=self._signed_request();r[field]=True;self._sign(r)
            with patch.object(m.recovery_verifier,'public_result',return_value=self._verified()):
                with self.subTest(field=field):self.assertIsNone(m._validate(r,self._ctx()))

    def test_missing_or_wrong_recovery_report_refused(self):
        r=self._signed_request()
        with patch.object(m.recovery_verifier,'public_result',return_value=None):
            self.assertIsNone(m._validate(r,self._ctx()))
        v=self._verified();v['sha256']='0'*64
        with patch.object(m.recovery_verifier,'public_result',return_value=v):
            self.assertIsNone(m._validate(r,self._ctx()))

    def test_worker_imports_only_with_exact_sha_and_readback(self):
        fake={'request_id':'mbst_'+'a'*32,'recovery_request_id':'mbr_'+'d'*32,
              'point_id':'mbrp_'+'c'*32,'node_id':'b'*64,'size':self.size,'sha':self.sha}
        folder=self.root/'quarantine';folder.mkdir()
        shutil.copyfile(self.archive,folder/(fake['recovery_request_id']+'.tar'))
        calls=[]
        def mock_call(method,route,token,archive=None):
            calls.append((method,route,archive is not None))
            if method=='GET' and route=='/backups':return {'backups':[]}
            if method=='POST':return {'slug':'deadbeef'}
            return {'slug':'deadbeef'}
        with patch.object(m,'_ROOT',folder),patch.object(m,'_META',folder/'stage_result.json'),\
             patch.object(m,'_call_supervisor',side_effect=mock_call),\
             patch.dict('os.environ',{'SUPERVISOR_TOKEN':'fake-test-token'}):
            m._worker(fake)
            self.assertEqual(m.public_result()['state'],'imported')
        self.assertEqual(calls,[('GET','/backups',False),('POST','/backups/new/upload',True),('GET','/backups/deadbeef/info',False)])
        self.assertTrue((folder/(fake['recovery_request_id']+'.tar')).exists())

    def test_existing_slug_never_overwritten(self):
        fake={'request_id':'mbst_'+'a'*32,'recovery_request_id':'mbr_'+'d'*32,
              'point_id':'mbrp_'+'c'*32,'node_id':'b'*64,'size':self.size,'sha':self.sha}
        folder=self.root/'quarantine';folder.mkdir()
        shutil.copyfile(self.archive,folder/(fake['recovery_request_id']+'.tar'))
        calls=[]
        def mock_call(method,route,token,archive=None):
            calls.append(route)
            return {'backups':[{'slug':'deadbeef'}]}
        with patch.object(m,'_ROOT',folder),patch.object(m,'_META',folder/'stage_result.json'),\
             patch.object(m,'_call_supervisor',side_effect=mock_call),patch.dict('os.environ',{'SUPERVISOR_TOKEN':'fake'}):
            m._worker(fake)
            self.assertEqual(m.public_result()['state'],'failed')
        self.assertEqual(calls,['/backups'])


    def test_http_upload_is_multipart_and_never_restore(self):
        body=[];paths=[]
        class FakeResponse:
            status=200
            def read(self,n):return json.dumps({'result':'ok','data':{'slug':'deadbeef'}}).encode()
        class FakeConn:
            def __init__(self,*a,**k):pass
            def putrequest(self,method,route):paths.append((method,route))
            def putheader(self,k,v):pass
            def endheaders(self):pass
            def send(self,blob):body.append(blob)
            def getresponse(self):return FakeResponse()
            def close(self):pass
        with patch.object(m.http.client,'HTTPConnection',FakeConn):
            result=m._call_supervisor('POST','/backups/new/upload','test-token',self.archive)
        self.assertEqual(result['slug'],'deadbeef')
        self.assertEqual(paths,[('POST','/backups/new/upload')])
        data=b''.join(body)
        self.assertIn(b'Content-Disposition: form-data;',data)
        self.assertIn(self.archive.read_bytes(),data)
        self.assertNotIn(b'/restore',data)

    def test_unexpected_supervisor_import_response_fails_closed(self):
        fake={'request_id':'mbst_'+'a'*32,'recovery_request_id':'mbr_'+'d'*32,
              'point_id':'mbrp_'+'c'*32,'node_id':'b'*64,'size':self.size,'sha':self.sha}
        folder=self.root/'quarantine';folder.mkdir()
        shutil.copyfile(self.archive,folder/(fake['recovery_request_id']+'.tar'))
        def mock_call(method,route,token,archive=None):
            return {'backups':[]} if route=='/backups' else {'slug':'wrong-slug'}
        with patch.object(m,'_ROOT',folder),patch.object(m,'_META',folder/'stage_result.json'),\
             patch.object(m,'_call_supervisor',side_effect=mock_call),patch.dict('os.environ',{'SUPERVISOR_TOKEN':'fake'}):
            m._worker(fake)
            result=m.public_result()
            self.assertEqual(result['state'],'failed')
            self.assertEqual(result['reason'],'supervisor_import_unconfirmed')

if __name__=='__main__':unittest.main()
