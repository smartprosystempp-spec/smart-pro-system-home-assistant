import json
import tempfile
import unittest
from pathlib import Path

import managed_zero_copy_device_proof as proof

NOW = 1793685000
IID = "ID-28422"
REF = "SPMZ-" + "A" * 32


def local_offer():
    return {
        "contract": "smart-pro-managed-zero-copy-local-offer-v1",
        "installation_id": IID, "request_ref": REF,
        "status": "pending_handoff", "expires_at": NOW + 590,
        "read_only": True, "claim_authorized": False,
        "identity_created": False, "runtime_authorized": False,
        "technician_access_granted": False,
    }


class DeviceProofTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = Path(self.tmp.name) / "device-key.json"
        self.challenge = Path(self.tmp.name) / "challenge.json"

    def build(self, offer=None, iid=IID, now=NOW):
        return proof.build_proof_payload(
            local_offer() if offer is None else offer, iid,
            key_path=self.key, challenge_path=self.challenge, now=now)

    def test_private_key_pinned_and_not_in_heartbeat(self):
        a, b = self.build(), self.build(now=NOW + 1)
        self.assertEqual(a["public_key_hex"], b["public_key_hex"])
        self.assertEqual(a["action"], "register")
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(a["signature_hex"]), 128)
        self.assertNotIn("private_seed_hex", a)
        self.assertNotIn("node_secret", a)

    def test_exact_installation_and_valid_offer_required(self):
        self.assertIsNone(self.build(offer={}))
        self.assertIsNone(self.build(iid="ID-99999"))
        self.assertFalse(self.key.exists())
        for field, value in [("claim_authorized", True), ("identity_created", True),
                             ("runtime_authorized", True), ("technician_access_granted", True),
                             ("read_only", False), ("expires_at", NOW)]:
            bad = dict(local_offer(), **{field: value})
            self.assertIsNone(self.build(offer=bad))
        self.assertFalse(self.key.exists())

    def test_challenge_proof_and_exact_binding(self):
        p = self.build()
        challenge = "e" * 64
        reply = {"installation_id": IID, "managed_zero_copy_device": {
            "contract": proof.CONTRACT, "status": "challenge_ready",
            "request_ref": REF, "challenge": challenge, "expires_at": NOW + 120,
        }}
        self.assertTrue(proof.accept_challenge_response(
            reply, local_offer(), IID, path=self.challenge, now=NOW))
        signed = self.build(now=NOW + 5)
        self.assertEqual(signed["public_key_hex"], p["public_key_hex"])
        self.assertEqual(signed["action"], "challenge_response")
        self.assertEqual(signed["challenge"], challenge)
        self.assertEqual(self.challenge.stat().st_mode & 0o777, 0o600)

    def test_corrupted_or_cross_installation_key_not_recreated(self):
        self.key.write_text("broken")
        self.key.chmod(0o600)
        self.assertIsNone(self.build())
        self.assertEqual(self.key.read_text(), "broken")
        self.key.unlink()
        a = self.build()
        other = dict(local_offer(), installation_id="ID-99999")
        self.assertIsNone(self.build(offer=other, iid="ID-99999"))
        self.assertEqual(self.build()["public_key_hex"], a["public_key_hex"])

    def test_reject_bad_or_stale_server_challenge(self):
        self.build()
        challenge = {"installation_id": IID, "managed_zero_copy_device": {
            "contract": proof.CONTRACT, "status": "challenge_ready",
            "request_ref": REF, "challenge": "b" * 64,
            "expires_at": NOW + 310,
        }}
        self.assertFalse(proof.accept_challenge_response(
            challenge, local_offer(), IID, path=self.challenge, now=NOW))
        self.assertFalse(self.challenge.exists())
        challenge["installation_id"] = "ID-99999"
        challenge["managed_zero_copy_device"]["expires_at"] = NOW + 100
        self.assertFalse(proof.accept_challenge_response(
            challenge, local_offer(), IID, path=self.challenge, now=NOW))

    def test_verified_receipt_purges_challenge_not_identity(self):
        self.build()
        reply = {"installation_id": IID, "managed_zero_copy_device": {
            "contract": proof.CONTRACT, "status": "challenge_ready",
            "request_ref": REF, "challenge": "f" * 64, "expires_at": NOW + 50,
        }}
        self.assertTrue(proof.accept_challenge_response(
            reply, local_offer(), IID, path=self.challenge, now=NOW))
        reply["managed_zero_copy_device"] = {
            "contract": proof.CONTRACT, "status": "verified", "request_ref": REF,
        }
        self.assertFalse(proof.accept_challenge_response(
            reply, local_offer(), IID, path=self.challenge, now=NOW + 1))
        self.assertFalse(self.challenge.exists())
        self.assertTrue(self.key.exists())


if __name__ == "__main__":
    unittest.main()
