SMART PRO ACCESS PREFLIGHT — 0.4.0 / LAB PERSISTENT ADMIN WITHOUT LOGIN
Changed-files ZIP for EXISTING GitHub repository; NOT standalone HA ZIP.
Extract ALL before upload. In GitHub root upload folders:
  docs/ smart-pro-access-preflight/ tests/
and two root files QA-RESULTS.txt + README-START-HERE.txt.
Existing root README.md and repository.yaml must NOT be replaced.
NO GitHub Publish Actions. Update ONLY the separate Smart Pro Access QA addon.

IMPORTANT: This creates a real HA administrator user record WITHOUT
username/password, not yet usable for Smart Pro sign-in or remote support.
The HA account remains after the QA addon is stopped; an explicit, separate
revoke is required. Do NOT try on production.

FIRST QA ONLY: Install 0.4.0 in TEST HA, open as administrator,
verify the account is ABSENT and send screenshot. DO NOT create yet.
Next steps, separately supervised: CREATE -> check Users -> stop/start addon
-> verify retention -> REVOKE -> check Users.

Existing local test user: Smart Pro QA User / smartpro_qa_user (non-admin).
Existing different user smartproqa 9 and Supervisor: DO NOT CHANGE.
Never copy personal passwords, identity tokens or full ingress URLs.
