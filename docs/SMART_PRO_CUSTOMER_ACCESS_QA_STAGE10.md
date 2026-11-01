# Smart Pro Customer Access — Stage 10 / Retained Non-Login Admin

Date: 2026-11-01
Add-on: `smart-pro-access-preflight` 0.4.0
Deployment: TEST Home Assistant only; NO production upgrade

## Evidence baseline

- 0.2.0 live admin + Core readback: PASS
- 0.2.0 normal user `Smart Pro QA User` denial: PASS
- 0.3.2 live fetch Origin valid, Origin/Host same, custom header yes,
  Sec-Fetch-Site missing: PASS (read-only)
- 0.3.3 live actual temporary HA admin create / verify / delete:
  `qa_account_created_verified_deleted`, user absent in Users: PASS
- 0.4.0 retention and revocation **NOT YET LIVE TESTED**

## Single-use lab target

Exact name: `Smart Pro QA RETAINED NO LOGIN`
Created by admin-approved Core `config/auth/create` with `system-admin`,
`local_only=True`. No provider credential setup, username, password,
refresh token or remote connection access. This account will **remain in HA**
until a separate admin-approved revoke or manual removal.

Readback accepts only exact name, one non-owner active (or inactive for
revoke) non-system account, admin group only, local_only True, zero
credentials. Ambiguous names or modified accounts block automatic writes.

## Independent approvals

CREATE: typed `ΔΗΜΙΟΥΡΓΙΑ`, admin-bound 180-sec CSRF, strict browser origin,
custom header, fresh Core admin readback, unique state check, one attempt.
REVOKE: typed `ΑΝΑΚΛΗΣΗ`, independent token, same verification, exact identity
and no-credentials readback, one attempt, post-delete confirmation.

## Live QA sequence

1. Install 0.4.0 only on disposable HA. FIRST screenshot with forms only.
2. Confirm no QA TEMP or QA RETAINED users exist.
3. Separate approved CREATE, screenshot result and Users inventory.
4. Stop/Start QA addon; verify retained user remains unchanged in HA.
5. Separate approved REVOKE; verify Users no longer contains retained user.
6. Confirm main Smart Pro System 3.0.28, Managed Support 3.19.2, Tunnel,
   and the existing local QA user are unaffected.

Emergency: if any result uncertain, *do not retry*; review Home Assistant
Settings → People → Users and use the HA administrator UI to remove **only**
the exact temporary account if appropriate. Never share passwords, tokens,
whole ingress URLs or user IDs in screenshots.

## Next technical project

Login-capable account creation and secure credential custody are a separate
hard security gate. Portal shall not store a recoverable administrator
password in plaintext or grant permanent privilege based solely on pairing.
