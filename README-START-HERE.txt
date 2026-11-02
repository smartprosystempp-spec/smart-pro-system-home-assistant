SMART PRO ACCESS PREFLIGHT — QA 0.6.0
REPOSITORY OVERLAY — not a Home Assistant add-on installable ZIP.

The repository contains Smart Pro Access Preflight 0.5.0 already.
Upload/replace only the enclosed smart-pro-access-preflight files
plus tests/test_access_handoff_qa.py and adapted legacy tests in tests/.
NO smart-pro-system, Managed Support or Tunnel files changed.
QA-only add-on builds locally from its own Dockerfile, no Action required.

INSTALL ORDER
1. FIRST live verify Portal 3.6.397: admin card should show NOT_RECEIVED on ID-75236.
2. ONLY AFTER Portal PASS, upload this QA overlay to GitHub main and update
   Smart Pro Access Preflight 0.5.0 -> 0.6.0 on TEST HA ID-75236.
3. STOP after visual QA. Do not arm Portal or approve account creation yet.

LATER LIVE TEST (not now)
- Admin Portal arm 15-minute ticket; never share it in screenshot/chat.
- In matching QA HA Access Preflight 0.6.0, verify HA admin and locally paired ID.
- Paste ticket, type ΠΑΡΑΔΟΣΗ, submit exactly once.
- Portal ENCRYPTED_RECEIVED; explicit no-store admin reveal and acknowledge.
- Copy password into your password manager; no plaintext in HA UI.
- Test local login, then explicit QA account revoke when testing complete.
On any uncertain/failed action, no retries before reviewing Portal/HA users.
