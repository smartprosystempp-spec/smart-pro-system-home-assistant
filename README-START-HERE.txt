SMART PRO ACCESS PREFLIGHT QA 0.6.1 — READ-ONLY HANDOFF DIAGNOSTIC

WHY THIS RELEASE
The first 0.6.0 live handoff returned a generic uncertain browser message.
The user confirmed NO QA LOGIN LAB account exists in HA; Admin Portal 3.6.397
remains WAITING_FOR_HA_APPROVAL. Root cause not yet proven.

CHANGED SOURCE (GITHUB MAIN OVERLAY)
- smart-pro-access-preflight/app.py
- smart-pro-access-preflight/consent_qa.py
- smart-pro-access-preflight/probe.js
- smart-pro-access-preflight/config.yaml
- smart-pro-access-preflight/Dockerfile
- smart-pro-access-preflight/README.md
- tests/test_access_core_gate.py (0.6.1 expected version)
- tests/test_access_preflight.py (0.6.1 expected version)
- tests/test_access_handoff_preflight_061.py (new)

Copy only the smart-pro-access-preflight and tests folders into the existing
smartprosystempp-spec/smart-pro-system-home-assistant GitHub main branch,
merging changes. DO NOT delete/recreate other folders.
No Smart Pro System image publish workflow is required for this QA add-on.

WHAT THE RELEASE ADDS
- A separate read-only ticket preflight button requiring a verified HA admin,
  a unique CSRF token, same-origin headers and a valid 15-minute Portal ticket.
- It returns only a bounded non-secret result code, never a ticket or key.
- No account create/delete, retry, secret delivery or production activation.
- 0.6.0 account creation remains independently confirmed and one-attempt only.

LIVE CHECKPOINT 1 (ONLY)
1. Update the Access Preflight QA app 0.6.0 -> 0.6.1 in TEST HA ID-75236.
2. Start the QA app if required; open Web UI as the normal HA admin.
3. Confirm new "Έλεγχος παράδοσης χωρίς δημιουργία" form appears.
4. STOP and send screenshot WITHOUT any ticket.

NEXT (AFTER FIRST SCREENSHOT)
If Portal 3.6.397 has expired its existing 15-minute ticket, arm a fresh
request ONLY after explicit instruction and use the read-only probe to
classify the failure before attempting any user creation. NEVER reuse or
share the bearer ticket and do NOT retry CREATE pending diagnosis.

NOTE: The earlier successful synthetic HA-to-Portal bridge remains unaffected.
