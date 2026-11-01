"""Stage-0 regression gates for customer-managed-access enrollment.

Run: python3 -m unittest discover -s tests -p 'test_customer_managed_access_foundation.py'

This test intentionally checks the NO-WRITE foundation only. Replace its
provisioning-absence assertions with stronger authorization/consent tests
before adding any production user-creation implementation.
"""

import re
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
PRIMARY = REPO / "smart-pro-system"
MANAGED = REPO / "smart-pro-managed-support"
CONTRACT = REPO / "docs" / "CUSTOMER_MANAGED_ACCESS_ENROLLMENT_FOUNDATION.md"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class CustomerManagedAccessStage0(unittest.TestCase):
    def test_primary_is_only_addon_with_home_assistant_admin_proxy(self):
        main_config = read(PRIMARY / "config.yaml")
        managed_config = read(MANAGED / "config.yaml")
        self.assertRegex(main_config, r"(?m)^homeassistant_api:\s*true\s*$")
        self.assertNotRegex(managed_config, r"(?m)^homeassistant_api:\s*true\s*$")
        self.assertNotRegex(managed_config, r"(?m)^auth_api:\s*true\s*$")

    def test_no_customer_user_creation_writer_yet(self):
        # STOP GATE: A future account writer needs new owner/consent security
        # proof and dedicated tests, never the existing browser/PIN handler.
        for addon in (PRIMARY, MANAGED):
            source = read(addon / "app.py")
            self.assertNotIn("config/auth/create", source)
            self.assertNotIn("config/auth_provider/homeassistant/create", source)

    def test_read_only_foundation_contract_is_explicit(self):
        contract = read(CONTRACT)
        for essential in (
            "Portal identity",
            "Local Home Assistant owner/admin approval",
            "Bound, one-time request",
            "Safe account lifecycle",
            "Credential policy not yet decided",
            "Revoke and audit",
            "No public write endpoint",
            "No runtime, version or production changes",
        ):
            with self.subTest(essential=essential):
                self.assertIn(essential, contract)

    def test_existing_managed_channel_remains_separate(self):
        config = read(MANAGED / "config.yaml")
        self.assertRegex(config, r"(?m)^ingress:\s*true\s*$")
        self.assertRegex(config, r"(?m)^host_network:\s*false\s*$")
        self.assertNotIn("homeassistant_api: true", config)
        self.assertNotIn("hassio_role: admin", config)


if __name__ == "__main__":
    unittest.main()
