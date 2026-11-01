"""Pure, isolated Stage-1 tests. No HA installation or network needed.

Run: python3 -m unittest discover -s tests -p 'test_customer_managed_access_admin_gate.py'
"""
import unittest

from customer_access_admin_gate import evaluate_local_admin_preflight

USER_ID = "0123456789abcdef0123456789abcdef"
INGRESS_PATH = "/api/hassio_ingress/abcDEF1234567890_/"


def good_context(**overrides):
    args = {
        "peer_ip": "172.30.32.2",
        "ingress_headers": {
            "X-Ingress-Path": INGRESS_PATH,
            "X-Remote-User-Id": USER_ID,
        },
        "ha_users": [{
            "id": USER_ID,
            "is_owner": False,
            "is_active": True,
            "system_generated": False,
            "group_ids": ["system-admin"],
        }],
        "paired_installation_id": "ID-95948",
        "requested_installation_id": "ID-95948",
    }
    args.update(overrides)
    return args


class CustomerManagedAccessAdminGateTests(unittest.TestCase):

    def assert_denied(self, reason, **changes):
        result = evaluate_local_admin_preflight(**good_context(**changes))
        self.assertEqual(result, {"eligible_for_next_step": False, "reason_code": reason})

    def test_admin_is_eligible_for_read_only_preflight(self):
        self.assertEqual(
            evaluate_local_admin_preflight(**good_context()),
            {"eligible_for_next_step": True, "reason_code": "ha_admin_identity_verified_read_only"},
        )

    def test_owner_is_eligible_for_read_only_preflight(self):
        user = dict(good_context()["ha_users"][0], is_owner=True, group_ids=[])
        self.assertTrue(evaluate_local_admin_preflight(
            **good_context(ha_users=[user]))["eligible_for_next_step"])

    def test_ordinary_home_assistant_user_is_denied(self):
        user = dict(good_context()["ha_users"][0], group_ids=["system-users"])
        self.assert_denied("ha_user_not_administrator", ha_users=[user])

    def test_read_only_user_is_denied(self):
        user = dict(good_context()["ha_users"][0], group_ids=["system-read-only"])
        self.assert_denied("ha_user_not_administrator", ha_users=[user])

    def test_inactive_administrator_is_denied(self):
        user = dict(good_context()["ha_users"][0], is_active=False)
        self.assert_denied("ha_user_inactive", ha_users=[user])

    def test_service_user_is_denied_even_if_admin(self):
        user = dict(good_context()["ha_users"][0], system_generated=True)
        self.assert_denied("ha_service_identity_not_allowed", ha_users=[user])

    def test_direct_browser_request_is_denied(self):
        self.assert_denied("not_supervisor_ingress", peer_ip="192.168.1.40")

    def test_forwarded_ip_cannot_replace_socket_peer(self):
        headers = dict(good_context()["ingress_headers"], **{
            "X-Forwarded-For": "172.30.32.2",
        })
        self.assert_denied(
            "not_supervisor_ingress",
            peer_ip="127.0.0.1",
            ingress_headers=headers,
        )

    def test_missing_ingress_path_is_denied(self):
        self.assert_denied(
            "ingress_session_unverified",
            ingress_headers={"X-Remote-User-Id": USER_ID},
        )

    def test_missing_user_header_is_denied(self):
        self.assert_denied(
            "ha_identity_missing",
            ingress_headers={"X-Ingress-Path": INGRESS_PATH},
        )

    def test_user_header_cannot_promote_normal_user(self):
        user = dict(good_context()["ha_users"][0], group_ids=["system-users"])
        headers = dict(good_context()["ingress_headers"], **{"X-Remote-User-Is-Admin": "true"})
        self.assert_denied("ha_user_not_administrator", ha_users=[user], ingress_headers=headers)

    def test_identity_must_match_readback(self):
        user = dict(good_context()["ha_users"][0], id="aaaabbbbccccddddeeeeffff00001111")
        self.assert_denied("ha_identity_not_found_or_ambiguous", ha_users=[user])

    def test_duplicate_identity_is_denied(self):
        user = good_context()["ha_users"][0]
        self.assert_denied("ha_identity_not_found_or_ambiguous", ha_users=[user, user])

    def test_failed_user_readback_is_denied(self):
        self.assert_denied("ha_user_readback_invalid", ha_users=None)

    def test_installation_must_match_exactly(self):
        self.assert_denied("installation_mismatch", requested_installation_id="ID-12345")

    def test_missing_local_installation_binding_denied(self):
        self.assert_denied("installation_binding_missing", paired_installation_id="")

    def test_invalid_group_data_denied(self):
        user = dict(good_context()["ha_users"][0], group_ids="system-admin")
        self.assert_denied("ha_groups_invalid", ha_users=[user])


if __name__ == "__main__":
    unittest.main()
