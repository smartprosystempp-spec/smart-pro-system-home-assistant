import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"smart-pro-managed-support"))
from managed_zero_copy_public_endpoint import public_receiver_offer, HOST_GATEWAY_PEER

NOW=1793685000
IID="ID-28422"
REF="SPMZ-"+"A"*32

def policy():
    return {"allowed_local": True, "policy": {
        "installation_id": IID, "manual_pause": False,
        "entitlement": {"managed_remote_support": True},
        "subscription": {"status": "active", "services_active": True, "using_cached_state": False},
        "health": {"portal_paired": True, "portal_sync_healthy": True},
    }}

def offer():
    return {"contract": "smart-pro-managed-zero-copy-local-offer-v1",
            "installation_id": IID, "request_ref": REF,
            "status": "pending_handoff", "expires_at": NOW+480,
            "read_only": True, "claim_authorized": False, "identity_created": False,
            "runtime_authorized": False, "technician_access_granted": False}

class PublicEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.op=Path(self.temp.name)/"offer.json"
        self.kp=Path(self.temp.name)/"key.json"
        self.op.write_text(json.dumps(offer()),encoding="utf-8")

    def check(self, peer=HOST_GATEWAY_PEER, local=None, identity=None, arch="amd64"):
        return public_receiver_offer(peer,policy() if local is None else local,identity,arch,
                                     offer_path=self.op,key_path=self.kp,now=NOW)

    def test_public_key_only_and_pinned(self):
        first=self.check()
        self.assertEqual(first["contract"],"smart-pro-managed-zero-copy-receiver-public-v1")
        self.assertEqual(first["request_ref"],REF)
        self.assertEqual(first["installation_id"],IID)
        self.assertFalse(first["claim_authorized"])
        self.assertFalse(first["identity_created"])
        self.assertNotIn("node_secret",first)
        self.assertNotIn("private_key_hex",first)
        self.assertEqual(first["receiver_public_key_hex"],self.check()["receiver_public_key_hex"])
        self.assertEqual(self.kp.stat().st_mode & 0o777,0o600)

    def test_ingress_and_other_addons_denied(self):
        for peer in ("172.30.32.2","172.30.33.4","127.0.0.1","192.168.1.1",""):
            self.assertIsNone(self.check(peer=peer))
        self.assertFalse(self.kp.exists())

    def test_existing_identity_stops_first_enrollment(self):
        self.assertIsNone(self.check(identity={"node_id":"already-bound"}))
        self.assertFalse(self.kp.exists())

    def test_inactive_or_stale_subscription_denied(self):
        for which in ("entitlement","status","services","cached","paired","sync","pause","local"):
            p=policy()
            if which=="entitlement":p["policy"]["entitlement"]["managed_remote_support"]=False
            if which=="status":p["policy"]["subscription"]["status"]="expired"
            if which=="services":p["policy"]["subscription"]["services_active"]=False
            if which=="cached":p["policy"]["subscription"]["using_cached_state"]=True
            if which=="paired":p["policy"]["health"]["portal_paired"]=False
            if which=="sync":p["policy"]["health"]["portal_sync_healthy"]=False
            if which=="pause":p["policy"]["manual_pause"]=True
            if which=="local":p["allowed_local"]=False
            self.assertIsNone(self.check(local=p),which)
        self.assertFalse(self.kp.exists())

    def test_wrong_offer_arch_and_expiry_denied(self):
        self.assertIsNone(self.check(arch="armv7"))
        self.op.write_text(json.dumps(dict(offer(),installation_id="ID-99999")))
        self.assertIsNone(self.check())
        self.op.write_text(json.dumps(dict(offer(),expires_at=NOW)))
        self.assertIsNone(self.check())
        self.op.unlink()
        self.assertIsNone(self.check())
        self.assertFalse(self.kp.exists())

    def test_no_silent_reseed_after_corruption(self):
        self.assertIsNotNone(self.check())
        self.kp.write_text("corrupt")
        self.kp.chmod(0o600)
        self.assertIsNone(self.check())
        self.assertEqual(self.kp.read_text(),"corrupt")

if __name__=="__main__":
    unittest.main()
