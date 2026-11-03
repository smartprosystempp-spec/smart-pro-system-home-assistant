"""Contract regression: read-only Managed enrollment offer; never permits actions."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "smart-pro-system"))
import managed_zero_copy_offer as zc

NOW = 1793684700
IID = "ID-28422"
REF = "SPMZ-" + "A" * 32

def valid():
    return {
        "installation_id": IID, "server_time": NOW,
        "managed_zero_copy_offer": {
            "contract": zc.CONTRACT, "installation_id": IID, "request_ref": REF,
            "issued_at": NOW - 10, "expires_at": NOW + 590,
            "status": "pending_handoff", "read_only": True,
            "claim_authorized": False, "identity_created": False,
            "runtime_authorized": False, "technician_access_granted": False,
        },
    }

class PassiveOfferTests(unittest.TestCase):
    def test_valid_bounded_non_authorizing_offer(self):
        record = zc.validate_passive_offer(valid(), IID, now=NOW)
        self.assertEqual(record["request_ref"], REF)
        self.assertFalse(record["claim_authorized"])
        self.assertFalse(record["identity_created"])
        self.assertNotIn("node_secret", record)
        self.assertNotIn("pairing_code", record)

    def test_cross_installation_denied(self):
        for field in ("installation_id", "offer_installation_id"):
            payload = valid()
            if field == "installation_id":
                payload["installation_id"] = "ID-11111"
            else:
                payload["managed_zero_copy_offer"]["installation_id"] = "ID-11111"
            self.assertIsNone(zc.validate_passive_offer(payload, IID, NOW))

    def test_all_permissions_must_be_explicitly_off(self):
        for key in ("read_only", "claim_authorized", "identity_created",
                    "runtime_authorized", "technician_access_granted"):
            for val in (True, False, None):
                payload = valid()
                payload["managed_zero_copy_offer"][key] = val
                if (key == "read_only" and val is True) or (key != "read_only" and val is False):
                    self.assertIsNotNone(zc.validate_passive_offer(payload, IID, NOW))
                else:
                    self.assertIsNone(zc.validate_passive_offer(payload, IID, NOW))
            payload = valid()
            del payload["managed_zero_copy_offer"][key]
            self.assertIsNone(zc.validate_passive_offer(payload, IID, NOW))

    def test_invalid_ref_expiry_clock_denied(self):
        for ref in ("", "SPMZ-123", "SPMZ-" + "G" * 32, REF.lower()):
            payload = valid()
            payload["managed_zero_copy_offer"]["request_ref"] = ref
            self.assertIsNone(zc.validate_passive_offer(payload, IID, NOW))
        for patch in ({"expires_at": NOW}, {"expires_at": NOW + 601},
                      {"issued_at": NOW + 1}, {"issued_at": NOW - 601},
                      {"expires_at": str(NOW + 10)}):
            payload = valid()
            payload["managed_zero_copy_offer"].update(patch)
            self.assertIsNone(zc.validate_passive_offer(payload, IID, NOW))
        payload = valid()
        payload["server_time"] = NOW + 301
        self.assertIsNone(zc.validate_passive_offer(payload, IID, NOW))

    def test_file_write_and_missing_offer_purge(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "share" / "managed-enrollment-offer.json"
            self.assertTrue(zc.consume_heartbeat_offer(valid(), IID, target, NOW))
            record = json.loads(target.read_text())
            self.assertEqual(record["contract"], zc.LOCAL_CONTRACT)
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)
            self.assertFalse(zc.consume_heartbeat_offer({"installation_id": IID}, IID, target, NOW))
            self.assertFalse(target.exists())

    def test_unpaired_never_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "offer.json"
            self.assertFalse(zc.consume_heartbeat_offer(valid(), "", target, NOW))
            self.assertFalse(target.exists())

if __name__ == "__main__":
    unittest.main()
