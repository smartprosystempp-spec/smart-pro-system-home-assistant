"""Offline-only Broker recovery client ↔ PHP sealed-envelope fixture.

No live server, addon start, Managed identity creation or installed plugin.
"""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "smart-pro-managed-support"))
from managed_zero_copy_receiver import prepare_receiver, private_delivery_context
from managed_zero_copy_transport_client import (
    BROKER_ORIGIN, DeliveryUnavailable, _post_contract,
    request_challenge, retrieve_original_candidate, transmit_persisted_ack,
)
from managed_zero_copy_identity_commit import commit_verified_identity

NOW = 1793685000
IID = "ID-28422"
REF = "SPMZ-" + "A" * 32


def pending():
    return {"contract": "smart-pro-managed-zero-copy-local-offer-v1",
            "installation_id": IID, "request_ref": REF, "status": "pending_handoff",
            "expires_at": NOW + 500, "read_only": True,
            "claim_authorized": False, "identity_created": False,
            "runtime_authorized": False, "technician_access_granted": False}


def broker_heartbeat():
    return {"node_id": "SPMN-" + "B"*32, "installation_ref": IID,
            "server_authorization": {
                "schema_version": 1, "installation_id": IID,
                "authorized": True, "valid_until": NOW + 500,
                "portal_paired": True, "managed_entitlement": True,
                "subscription_status": "active", "managed_relationship_state": "enrolled",
                "remote_access": False, "meshcentral": False,
            }}


def local_policy():
    return {"allowed_local": True, "policy": {
        "installation_id": IID, "manual_pause": False,
        "entitlement": {"managed_remote_support": True},
        "subscription": {"status": "active", "services_active": True,
                         "using_cached_state": False},
        "health": {"portal_paired": True, "portal_sync_healthy": True},
    }}


class OfflineClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.key = Path(self.temp.name) / "receiver.json"
        self.identity = Path(self.temp.name) / "managed-identity.json"
        public = prepare_receiver(pending(), IID, key_path=self.key, now=NOW)
        self.assertIsInstance(public, dict)
        self.context = private_delivery_context(IID, REF, key_path=self.key, now=NOW + 1)
        self.assertTrue(self.context["not_a_bearer_grant"])
        fixture = {"installation_id": IID, "request_ref": REF,
                   "receiver_public_key_hex": public["public_key_hex"],
                   "architecture": "amd64",
                   "issued_at": NOW, "expires_at": NOW + 120}
        proc = subprocess.run(
            ["php", str(ROOT / "tests/fixtures/managed_zero_copy_delivery.php")],
            input=json.dumps(fixture).encode(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=True, timeout=10)
        self.fixture = json.loads(proc.stdout)
        self.calls = []

    def sender(self, endpoint, body):
        self.calls.append((endpoint, dict(body)))
        if endpoint == "delivery/challenge":
            return dict(self.fixture["challenge"])
        if endpoint == "delivery/fetch":
            self.assertEqual(body["proof_hex"], self.fixture["expected_proof"])
            return {
                "contract": "smart-pro-managed-zero-copy-original-delivery-v1",
                "installation_id": IID, "request_ref": REF,
                "receiver_public_key_hex": self.context["receiver_public_key_hex"],
                "architecture": "amd64",
                "envelope_sha256": self.fixture["envelope_sha256"],
                "original_envelope_json": self.fixture["original_envelope_json"],
                "identity_reissued": False, "identity_persisted": False,
                "runtime_authorized": False, "technician_access_granted": False,
            }
        if endpoint == "identity/ack":
            self.assertEqual(body["node_id"], "SPMN-" + "B"*32)
            self.assertEqual(body["node_secret"], "SPMS-" + "c"*43)
            return {"contract": "smart-pro-managed-zero-copy-identity-ack-v1",
                    "installation_id": IID, "request_ref": REF,
                    "status": "verified", "already_verified": len(self.calls) > 3,
                    "runtime_authorized": False, "technician_access_granted": False}
        raise AssertionError("unexpected request")

    def test_broker_origin_is_immutable(self):
        self.assertEqual(BROKER_ORIGIN, "https://api.smart-pro-system.gr")
        with self.assertRaises(DeliveryUnavailable):
            _post_contract("https://invalid.example/steal", {})
        with self.assertRaises(DeliveryUnavailable):
            _post_contract("managed/heartbeat", {})

    def test_original_delivery_no_secret_through_tools(self):
        challenge = request_challenge(
            self.context, "amd64", transport=self.sender, now=NOW + 1)
        self.assertIsInstance(challenge, dict)
        candidate = retrieve_original_candidate(
            self.context, "amd64", challenge, transport=self.sender,
            key_path=self.key, now=NOW + 1)
        self.assertEqual(candidate["node_secret"], "SPMS-" + "c" * 43)
        self.assertFalse(candidate["server_authorized"])
        self.assertFalse(candidate["identity_persisted"])
        self.assertEqual([x[0] for x in self.calls],
                         ["delivery/challenge", "delivery/fetch"])
        for endpoint, payload in self.calls:
            self.assertNotIn("node_secret", payload, endpoint)
            self.assertNotIn("node_id", payload, endpoint)
        self.assertFalse(self.identity.exists())

    def test_commit_after_broker_heartbeat_then_one_ack(self):
        challenge = request_challenge(
            self.context, "amd64", transport=self.sender, now=NOW + 1)
        candidate = retrieve_original_candidate(
            self.context, "amd64", challenge, transport=self.sender,
            key_path=self.key, now=NOW + 1)
        result = commit_verified_identity(
            candidate, broker_heartbeat(), local_policy(),
            identity_path=self.identity, now=NOW + 1)
        self.assertEqual(result["state"], "committed")
        self.assertEqual(self.identity.stat().st_mode & 0o777, 0o600)
        receipt = transmit_persisted_ack(
            IID, transport=self.sender, identity_path=self.identity)
        self.assertEqual(receipt["status"], "verified")
        self.assertFalse(receipt["runtime_authorized"])
        again = transmit_persisted_ack(
            IID, transport=self.sender, identity_path=self.identity)
        self.assertTrue(again["already_verified"])
        self.assertEqual(len([x for x in self.calls if x[0] == "identity/ack"]), 2)
        self.assertEqual(json.loads(self.identity.read_text())["node_id"],
                         "SPMN-" + "B"*32)

    def test_fail_closed_expired_or_tampered_challenge(self):
        self.assertIsNone(request_challenge(
            self.context, "amd64", transport=self.sender, now=NOW + 500))
        self.assertEqual(self.calls, [])
        challenge = request_challenge(
            self.context, "amd64", transport=self.sender, now=NOW + 1)
        challenge["sealed_box_hex"] = "0"*len(challenge["sealed_box_hex"])
        self.assertIsNone(retrieve_original_candidate(
            self.context, "amd64", challenge, transport=self.sender,
            key_path=self.key, now=NOW + 1))
        self.assertEqual([x[0] for x in self.calls], ["delivery/challenge"])
        self.assertFalse(self.identity.exists())

    def test_no_ack_from_missing_or_legacy_identity(self):
        self.assertIsNone(transmit_persisted_ack(
            IID, transport=self.sender, identity_path=self.identity))
        self.identity.write_text(json.dumps({
            "installation_id": IID, "node_id": "SPMN-"+"B"*32,
            "node_secret": "SPMS-"+"c"*43
        }))
        self.identity.chmod(0o600)
        self.assertIsNone(transmit_persisted_ack(
            IID, transport=self.sender, identity_path=self.identity))
        self.assertEqual(self.calls, [])

    def test_transport_failure_never_leaks_payload(self):
        def raise_error(endpoint, body):
            raise RuntimeError("sensitive traceback")
        self.assertIsNone(request_challenge(
            self.context, "amd64", transport=raise_error, now=NOW + 1))

if __name__ == "__main__":
    unittest.main()
