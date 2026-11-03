"""Synthetic PHP→Python original encrypted identity recovery. No live endpoints."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "smart-pro-managed-support"))
from managed_zero_copy_receiver import prepare_receiver
from managed_zero_copy_delivery import prove_receiver_challenge, verify_original_delivery

NOW = 1793685000
IID = "ID-28422"
REF = "SPMZ-" + "A" * 32

def offer():
    return {
        "contract": "smart-pro-managed-zero-copy-local-offer-v1",
        "installation_id": IID, "request_ref": REF,
        "status": "pending_handoff", "expires_at": NOW + 500,
        "read_only": True, "claim_authorized": False, "identity_created": False,
        "runtime_authorized": False, "technician_access_granted": False,
    }

class OriginalDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.key = Path(self.temp.name) / "receiver.json"
        public = prepare_receiver(offer(), IID, key_path=self.key, now=NOW)
        self.assertIsInstance(public, dict)
        fixture = {
            "installation_id": IID, "request_ref": REF,
            "receiver_public_key_hex": public["public_key_hex"],
            "architecture": "amd64", "issued_at": NOW, "expires_at": NOW + 120,
        }
        proc = subprocess.run(
            ["php", str(ROOT / "tests/fixtures/managed_zero_copy_delivery.php")],
            input=json.dumps(fixture).encode(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=True, timeout=10)
        self.generated = json.loads(proc.stdout)
        self.assertEqual(self.generated["envelope_sha256"],
                         hashlib.sha256(self.generated["original_envelope_json"].encode()).hexdigest())

    def proof(self, challenge=None, local_offer=None, now=NOW):
        return prove_receiver_challenge(
            self.generated["challenge"] if challenge is None else challenge,
            offer() if local_offer is None else local_offer, IID, "amd64",
            key_path=self.key, now=now)

    def delivery(self, **updates):
        public = self.generated["challenge"]["receiver_public_key_hex"]
        response = {
            "contract": "smart-pro-managed-zero-copy-original-delivery-v1",
            "installation_id": IID, "request_ref": REF,
            "receiver_public_key_hex": public, "architecture": "amd64",
            "envelope_sha256": self.generated["envelope_sha256"],
            "original_envelope_json": self.generated["original_envelope_json"],
            "identity_reissued": False, "identity_persisted": False,
            "runtime_authorized": False, "technician_access_granted": False,
        }
        response.update(updates)
        return response

    def open(self, delivery=None, proof=None, now=NOW):
        return verify_original_delivery(
            self.delivery() if delivery is None else delivery,
            self.proof() if proof is None else proof,
            offer(), IID, "amd64", key_path=self.key, now=now)

    def test_php_python_challenge_proof_and_original_identity(self):
        proof = self.proof()
        self.assertEqual(proof["proof_hex"], self.generated["expected_proof"])
        candidate = self.open(proof=proof)
        self.assertEqual(candidate["node_id"], "SPMN-" + "B" * 32)
        self.assertEqual(candidate["node_secret"], "SPMS-" + "c" * 43)
        self.assertTrue(candidate["delivery_proof_verified"])
        self.assertFalse(candidate["identity_persisted"])
        self.assertFalse(candidate["runtime_authorized"])
        self.assertEqual(sorted(p.name for p in Path(self.temp.name).iterdir()), ["receiver.json"])

    def test_lost_response_yields_exact_same_ciphertext(self):
        p = self.proof()
        one = self.open(proof=p)
        two = self.open(proof=p)
        self.assertEqual(one["original_envelope_sha256"], two["original_envelope_sha256"])
        self.assertEqual(one["node_id"], two["node_id"])
        self.assertFalse(one["identity_persisted"])

    def test_challenge_is_not_credentials(self):
        packet = self.generated["challenge"]
        serial = json.dumps(packet)
        self.assertNotIn("SPMS-", serial)
        self.assertNotIn("SPMN-", serial)
        self.assertEqual(len(self.proof()["proof_hex"]), 64)

    def test_wrong_key_and_changed_challenge_denied(self):
        bad = dict(self.generated["challenge"], request_ref="SPMZ-" + "C" * 32)
        self.assertIsNone(self.proof(challenge=bad))
        bad = dict(self.generated["challenge"], envelope_sha256="0" * 64)
        self.assertIsNone(self.proof(challenge=bad))
        bad = dict(self.generated["challenge"], sealed_box_hex="0" *
                   len(self.generated["challenge"]["sealed_box_hex"]))
        self.assertIsNone(self.proof(challenge=bad))
        bad = dict(self.generated["challenge"], identity_created=True)
        self.assertIsNone(self.proof(challenge=bad))
        with tempfile.TemporaryDirectory() as temp:
            newkey = Path(temp) / "receiver.json"
            prepare_receiver(offer(), IID, key_path=newkey, now=NOW)
            self.assertIsNone(prove_receiver_challenge(
                self.generated["challenge"], offer(), IID, "amd64",
                key_path=newkey, now=NOW))

    def test_envelope_tampering_or_wrong_binding_denied(self):
        original = self.generated["original_envelope_json"]
        self.assertIsNone(self.open(delivery=self.delivery(
            original_envelope_json=original + " ")))
        self.assertIsNone(self.open(delivery=self.delivery(
            envelope_sha256="f" * 64)))
        self.assertIsNone(self.open(delivery=self.delivery(
            request_ref="SPMZ-" + "C" * 32)))
        self.assertIsNone(self.open(delivery=self.delivery(
            architecture="aarch64")))
        self.assertIsNone(self.open(delivery=self.delivery(
            identity_reissued=True)))
        self.assertIsNone(self.open(delivery=self.delivery(
            runtime_authorized=True)))

    def test_ttl_denial_and_context_bound(self):
        self.assertIsNone(self.proof(now=NOW + 90))
        self.assertIsNone(self.open(now=NOW + 90))
        self.assertIsNone(self.open(now=NOW + 120))
        self.assertIsNone(self.proof(local_offer=dict(offer(),
                             installation_id="ID-99999")))
        self.assertIsNone(self.proof(local_offer=dict(offer(),
                             claim_authorized=True)))

if __name__ == "__main__":
    unittest.main()
