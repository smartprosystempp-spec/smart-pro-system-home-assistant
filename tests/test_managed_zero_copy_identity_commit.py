"""Offline-only identity file commit from authenticated Broker heartbeat response."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "smart-pro-managed-support"))
from managed_zero_copy_identity_commit import (
    commit_verified_identity, authenticated_ack_payload, RECEIPT_CONTRACT
)

NOW = 1793685000
IID = "ID-28422"
REF = "SPMZ-" + "A" * 32
NODE = "SPMN-" + "B" * 32
SECRET = "SPMS-" + "c" * 43
DIGEST = "d" * 64


def candidate():
    return {
        "installation_id": IID, "request_ref": REF, "node_id": NODE,
        "node_secret": SECRET, "original_envelope_sha256": DIGEST,
        "verified_cryptographically": True, "delivery_proof_verified": True,
        "server_authorized": False, "identity_persisted": False,
        "runtime_authorized": False,
    }


def reply():
    return {
        "node_id": NODE, "installation_ref": IID,
        "server_authorization": {
            "schema_version": 1, "installation_id": IID,
            "valid_until": NOW + 600, "authorized": True,
            "portal_paired": True, "managed_entitlement": True,
        },
    }


def policy():
    return {
        "allowed_local": True, "policy": {
            "installation_id": IID, "manual_pause": False,
            "entitlement": {"managed_remote_support": True},
            "subscription": {
                "status": "active", "services_active": True,
                "using_cached_state": False,
            },
            "health": {"portal_paired": True, "portal_sync_healthy": True},
        },
    }


class CommitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.target = Path(self.tmp.name) / "data" / "managed-identity.json"

    def commit(self, c=None, r=None, p=None, now=NOW):
        return commit_verified_identity(
            candidate() if c is None else c, reply() if r is None else r,
            policy() if p is None else p,
            identity_path=self.target, now=now)

    def test_success_private_and_receipt_in_one_file(self):
        result = self.commit()
        self.assertEqual(result, {"ok": True, "state": "committed"})
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)
        stored = json.loads(self.target.read_text())
        self.assertEqual(stored["node_id"], NODE)
        self.assertEqual(stored["node_secret"], SECRET)
        self.assertEqual(stored["installation_id"], IID)
        self.assertEqual(stored["zero_copy_receipt"]["contract"], RECEIPT_CONTRACT)
        self.assertEqual(stored["zero_copy_receipt"]["request_ref"], REF)
        self.assertFalse(stored["zero_copy_receipt"]["delivery_acknowledged"])
        self.assertNotIn("node_secret", result)
        self.assertNotIn("identity", result)

    def test_same_original_is_idempotent_but_different_denied(self):
        self.assertTrue(self.commit()["ok"])
        self.assertEqual(self.commit(), {"ok": True, "state": "already_committed"})
        for changed in (
            {"node_secret": "SPMS-" + "x" * 43},
            {"request_ref": "SPMZ-" + "C" * 32},
            {"original_envelope_sha256": "f" * 64},
            {"node_id": "SPMN-" + "D" * 32},
        ):
            cand = dict(candidate(), **changed)
            expected = "verification_denied" if "node_id" in changed else "identity_conflict"
            self.assertEqual(self.commit(c=cand)["state"], expected)
        self.assertEqual(json.loads(self.target.read_text())["node_secret"], SECRET)

    def test_broker_must_authorize_exact_node(self):
        cases = (
            {"node_id": "SPMN-" + "D" * 32},
            {"installation_ref": "ID-99999"},
        )
        for patch in cases:
            value = dict(reply(), **patch)
            self.assertEqual(self.commit(r=value)["state"], "verification_denied")
        for patch in (
            {"authorized": False}, {"portal_paired": False},
            {"managed_entitlement": False}, {"installation_id": "ID-99999"},
            {"valid_until": NOW + 10}, {"schema_version": 2},
        ):
            value = reply()
            value["server_authorization"].update(patch)
            self.assertEqual(self.commit(r=value)["state"], "verification_denied")
        self.assertFalse(self.target.exists())

    def test_policy_must_be_fresh_and_paid(self):
        for field in ("allowed", "iid", "paused", "entitled", "status", "services",
                      "cached", "portal", "sync"):
            p = policy()
            if field == "allowed": p["allowed_local"] = False
            if field == "iid": p["policy"]["installation_id"] = "ID-99999"
            if field == "paused": p["policy"]["manual_pause"] = True
            if field == "entitled": p["policy"]["entitlement"]["managed_remote_support"] = False
            if field == "status": p["policy"]["subscription"]["status"] = "expired"
            if field == "services": p["policy"]["subscription"]["services_active"] = False
            if field == "cached": p["policy"]["subscription"]["using_cached_state"] = True
            if field == "portal": p["policy"]["health"]["portal_paired"] = False
            if field == "sync": p["policy"]["health"]["portal_sync_healthy"] = False
            self.assertEqual(self.commit(p=p)["state"], "verification_denied", field)
        self.assertFalse(self.target.exists())

    def test_candidate_permissions_and_proofs_mandatory(self):
        for field, value in (
            ("verified_cryptographically", False), ("delivery_proof_verified", False),
            ("server_authorized", True), ("identity_persisted", True),
            ("runtime_authorized", True), ("node_secret", "wrong"),
            ("request_ref", "SPMZ-invalid"),
        ):
            cand = dict(candidate(), **{field: value})
            self.assertEqual(self.commit(c=cand)["state"], "verification_denied", field)
        self.assertFalse(self.target.exists())

    def test_corrupt_identity_symlink_conflict_and_no_replacement(self):
        self.target.parent.mkdir(parents=True)
        self.target.write_text("INVALID", encoding="utf-8")
        self.target.chmod(0o600)
        self.assertEqual(self.commit()["state"], "identity_conflict")
        self.assertEqual(self.target.read_text(), "INVALID")
        self.target.unlink()
        symlink_target = self.target.parent / "real.json"
        symlink_target.write_text("IMMUTABLE")
        self.target.symlink_to(symlink_target)
        self.assertEqual(self.commit()["state"], "identity_conflict")
        self.assertEqual(symlink_target.read_text(), "IMMUTABLE")

    def test_ack_requires_private_receipt_and_exact_installation(self):
        self.assertIsNone(authenticated_ack_payload(self.target, IID))
        self.assertEqual(self.commit()["state"], "committed")
        ack = authenticated_ack_payload(self.target, IID)
        self.assertEqual(ack["contract"], "smart-pro-managed-zero-copy-identity-ack-v1")
        self.assertEqual(ack["node_id"], NODE)
        self.assertEqual(ack["node_secret"], SECRET)
        self.assertEqual(ack["envelope_sha256"], DIGEST)
        self.assertFalse(ack["runtime_authorized"])
        self.assertIsNone(authenticated_ack_payload(self.target, "ID-99999"))
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)

    def test_missing_receipt_or_legacy_identity_does_not_ack(self):
        self.target.parent.mkdir(parents=True)
        self.target.write_text(json.dumps({
            "installation_id": IID, "node_id": NODE, "node_secret": SECRET}))
        self.target.chmod(0o600)
        self.assertIsNone(authenticated_ack_payload(self.target, IID))
        self.assertEqual(self.commit()["state"], "identity_conflict")

    def test_key_mode_enforced_for_ack(self):
        self.assertEqual(self.commit()["state"], "committed")
        self.target.chmod(0o644)
        self.assertIsNone(authenticated_ack_payload(self.target, IID))
        self.assertEqual(self.commit()["state"], "identity_conflict")

if __name__ == "__main__":
    unittest.main()
