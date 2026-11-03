import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"smart-pro-system"))
from managed_zero_copy_receiver_transport import (
    ADDON_SLUG, PORT, PUBLIC_ENDPOINT, get_receiver_public,
    validated_ip_from_supervisor, build_pinned_receiver_proof,
)
from managed_zero_copy_device_proof import _key_for
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

NOW=1793685000
IID="ID-28422"
REF="SPMZ-"+"A"*32
PUB="b"*64
IP="172.30.33.7"

def offer():
    return {"contract":"smart-pro-managed-zero-copy-local-offer-v1",
            "installation_id":IID,"request_ref":REF,"status":"pending_handoff",
            "expires_at":NOW+450,"read_only":True,"claim_authorized":False,
            "identity_created":False,"runtime_authorized":False,"technician_access_granted":False}

def supervisor():
    return {"result":"ok","data":{
        "slug":ADDON_SLUG,"state":"started","ingress_port":PORT,
        "host_network":False,"ip_address":IP}}

def public():
    return {"contract":"smart-pro-managed-zero-copy-receiver-public-v1",
            "installation_id":IID,"request_ref":REF,"receiver_public_key_hex":PUB,
            "expires_at":NOW+450,"architecture":"amd64","read_only":True,
            "claim_authorized":False,"identity_created":False,
            "runtime_authorized":False,"technician_access_granted":False}

class Response:
    status=200
    def __init__(self,payload):self.payload=payload
    def getheader(self,name,default=""):return "application/json"
    def read(self,n):return json.dumps(self.payload).encode()

class Factory:
    def __init__(self,s=None,p=None):
        self.s=s or supervisor()
        self.p=p or public()
        self.requests=[]
    def __call__(self,host,port,timeout=3):
        outer=self
        class Conn:
            def request(self,verb,path,headers=None):
                outer.requests.append((host,port,verb,path,headers))
            def getresponse(self):
                return Response(outer.s if host=="supervisor" else outer.p)
            def close(self):pass
        return Conn()

class ReceiverTransportTests(unittest.TestCase):
    def test_supervisor_exact_target(self):
        self.assertEqual(validated_ip_from_supervisor(supervisor()),IP)
        for change in (
            {"data":{"slug":"other","ip_address":IP}},
            {"data":{"slug":ADDON_SLUG,"state":"stopped","ip_address":IP}},
            {"data":{"slug":ADDON_SLUG,"state":"started","ip_address":"8.8.8.8"}},
            {"data":{"slug":ADDON_SLUG,"state":"started","ip_address":"127.0.0.1"}},
            {"data":{"slug":ADDON_SLUG,"state":"started","ip_address":"172.30.32.1"}},
        ):
            bad=supervisor()
            bad["data"].update(change["data"])
            self.assertIsNone(validated_ip_from_supervisor(bad))

    def test_success_and_no_supervisor_token_forward(self):
        factory=Factory()
        self.assertEqual(get_receiver_public(offer(),IID,"amd64",
            supervisor_token="test-supervisor-private",connection_factory=factory,now=NOW),PUB)
        self.assertEqual(len(factory.requests),2)
        s,m=factory.requests
        self.assertEqual(s[0],"supervisor")
        self.assertEqual(s[3],f"/addons/{ADDON_SLUG}/info")
        self.assertEqual(s[4]["Authorization"],"Bearer test-supervisor-private")
        self.assertEqual(m[0],IP)
        self.assertEqual(m[1],PORT)
        self.assertEqual(m[3],PUBLIC_ENDPOINT)
        self.assertNotIn("Authorization",m[4])

    def test_supervisor_mismatch_never_calls_other_ip(self):
        bad=supervisor()
        bad["data"]["slug"]="unknown"
        f=Factory(s=bad)
        self.assertIsNone(get_receiver_public(offer(),IID,"amd64",
            supervisor_token="private",connection_factory=f,now=NOW))
        self.assertEqual(len(f.requests),1)

    def test_wrong_offer_response_and_expiry_denied(self):
        for mutated in (
            {"receiver_public_key_hex":"not_hex"},
            {"request_ref":"SPMZ-"+"B"*32},
            {"installation_id":"ID-99999"},
            {"claim_authorized":True},
            {"architecture":"aarch64"},
            {"expires_at":NOW+20},
        ):
            d=public()
            d.update(mutated)
            f=Factory(p=d)
            self.assertIsNone(get_receiver_public(offer(),IID,"amd64",
                supervisor_token="private",connection_factory=f,now=NOW))
        f=Factory()
        self.assertIsNone(get_receiver_public(dict(offer(),expires_at=NOW),
            IID,"amd64",supervisor_token="private",connection_factory=f,now=NOW))
        self.assertEqual(f.requests,[])

    def test_signed_pinned_receiver_key(self):
        with tempfile.TemporaryDirectory() as temp:
            key=Path(temp)/"tools-key.json"
            f=Factory()
            result=build_pinned_receiver_proof(offer(),IID,"amd64",
                key_path=key,supervisor_token="private",
                connection_factory=f,now=NOW)
            self.assertEqual(result["receiver_public_key_hex"],PUB)
            self.assertFalse(result["claim_authorized"])
            public_key=_key_for(IID,key)[1]
            message=f"SPMZ1|receiver_binding|{IID}|{REF}|{PUB}|amd64|{NOW}".encode()
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(
                bytes.fromhex(result["signature_hex"]),message)
            self.assertNotIn("private_seed_hex",result)

if __name__=="__main__":
    unittest.main()
