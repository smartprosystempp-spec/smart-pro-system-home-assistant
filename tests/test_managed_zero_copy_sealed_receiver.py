"""Synthetic-only Broker PHP <-> Managed Support Python sealed envelope contract."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "smart-pro-managed-support"))
from managed_zero_copy_receiver import prepare_receiver, open_candidate_envelope

NOW = 1793685000
IID = "ID-28422"
REF = "SPMZ-" + "A" * 32
NODE = "SPMN-" + "B" * 32
SECRET = "SPMS-" + "c" * 43


def offer():
    return {"contract": "smart-pro-managed-zero-copy-local-offer-v1",
            "installation_id": IID, "request_ref": REF, "status": "pending_handoff",
            "expires_at": NOW + 600, "read_only": True,
            "claim_authorized": False, "identity_created": False,
            "runtime_authorized": False, "technician_access_granted": False}


class SealedReceiverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.keyfile = Path(self.temp.name) / "receiver.json"
        self.public = prepare_receiver(offer(), IID, key_path=self.keyfile, now=NOW)

    def seal(self, **changes):
        payload = {
            "installation_id": IID, "request_ref": REF,
            "receiver_public_key_hex": self.public["public_key_hex"],
            "node_id": NODE, "node_secret": SECRET,
            "architecture": "amd64", "issued_at": NOW,
            "expires_at": NOW + 120,
        }
        payload.update(changes)
        process = subprocess.run(
            ["php", str(ROOT / "tests/fixtures/managed_zero_copy_seal.php")],
            input=json.dumps(payload).encode(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=True, timeout=10,
        )
        return json.loads(process.stdout)

    def open(self, envelope, *, local_offer=None, iid=IID, arch="amd64", now=NOW):
        return open_candidate_envelope(
            envelope, offer() if local_offer is None else local_offer,
            iid, arch, key_path=self.keyfile, now=now)

    def test_interoperability_and_no_plaintext(self):
        self.assertEqual(self.keyfile.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("private_key_hex", self.public)
        packet = self.seal()
        self.assertNotIn(SECRET, json.dumps(packet))
        self.assertNotIn(NODE, json.dumps(packet))
        result = self.open(packet)
        self.assertEqual(result["node_id"], NODE)
        self.assertEqual(result["node_secret"], SECRET)
        self.assertTrue(result["verified_cryptographically"])
        self.assertFalse(result["server_authorized"])
        self.assertFalse(result["identity_persisted"])
        self.assertFalse(result["runtime_authorized"])

    def test_wrong_request_and_installation_denied(self):
        packet = self.seal()
        self.assertIsNone(self.open(packet, iid="ID-99999"))
        self.assertIsNone(self.open(dict(packet, request_ref="SPMZ-"+"C"*32)))
        self.assertIsNone(self.open(dict(packet, installation_id="ID-99999")))
        self.assertIsNone(self.open(packet, local_offer={}))
        self.assertIsNone(self.open(packet, local_offer=dict(offer(), request_ref="SPMZ-"+"C"*32)))

    def test_expiry_and_arch_binding(self):
        packet = self.seal()
        self.assertIsNone(self.open(packet, arch="aarch64"))
        self.assertIsNone(self.open(packet, now=NOW + 120))
        self.assertIsNone(self.open(self.seal(expires_at=NOW + 601)))
        self.assertIsNone(self.open(self.seal(architecture="i386")))
        self.assertEqual(self.seal(node_secret="INVALID"), {})

    def test_wrong_receiver_private_key_and_cipher_mutation(self):
        packet = self.seal()
        with tempfile.TemporaryDirectory() as temp:
            other = Path(temp) / "receiver.json"
            another = prepare_receiver(offer(), IID, key_path=other, now=NOW)
            self.assertNotEqual(another["public_key_hex"], self.public["public_key_hex"])
            self.assertIsNone(open_candidate_envelope(
                packet, offer(), IID, "amd64", key_path=other, now=NOW))
        tampered = dict(packet, sealed_box_hex=("0" if packet["sealed_box_hex"][0] != "0" else "1")
                                           + packet["sealed_box_hex"][1:])
        self.assertIsNone(self.open(tampered))
        self.assertIsNone(self.open(dict(packet, runtime_authorized=True)))
        self.assertIsNone(self.open(dict(packet, technician_access_granted=True)))

    def test_no_silent_reseed_or_cross_installation(self):
        first = self.public["public_key_hex"]
        self.assertEqual(prepare_receiver(offer(), IID, key_path=self.keyfile, now=NOW)["public_key_hex"], first)
        self.assertIsNone(prepare_receiver(
            dict(offer(), request_ref="SPMZ-"+"C"*32), IID,
            key_path=self.keyfile, now=NOW))
        self.assertIsNone(prepare_receiver(
            offer(), "ID-99999", key_path=self.keyfile, now=NOW))
        self.keyfile.write_text("corrupt")
        self.keyfile.chmod(0o600)
        self.assertIsNone(prepare_receiver(offer(), IID, key_path=self.keyfile, now=NOW))
        self.assertEqual(self.keyfile.read_text(), "corrupt")

    def test_all_off_flags_required(self):
        for k in ("read_only", "claim_authorized", "identity_created",
                  "runtime_authorized", "technician_access_granted"):
            bad = dict(offer(), **{k: not offer()[k]})
            self.assertIsNone(prepare_receiver(
                bad, IID, key_path=Path(self.temp.name)/("other-"+k), now=NOW))

    def test_no_identity_file_created(self):
        self.open(self.seal())
        self.assertEqual(sorted(p.name for p in Path(self.temp.name).iterdir()), ["receiver.json"])


if __name__ == "__main__":
    unittest.main()
