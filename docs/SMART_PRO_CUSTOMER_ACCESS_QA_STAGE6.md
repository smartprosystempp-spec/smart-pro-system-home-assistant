# Smart Pro Customer Access — Stage 6: controlled no-login admin create/delete

**Date:** 2026-11-01  
**QA add-on:** Smart Pro Access Preflight **0.3.0**  
**Scope:** Test Home Assistant ONLY; fail-closed, explicit authorized human consent, bounded transient user write. **No customer enrollment.**

## Verified before this stage

- 0.1.0: Supervisor Ingress detects real HA admin and rejects `smartpro_qa_user` (non-admin) in live test.
- 0.2.0: Core `config/auth/list` confirms the exact active administrator; non-admin still rejected. Live QA FULL PASS.
- 0.3.0: internal isolated tests only until the two-stage live QA is performed.

## Exact technical write contract

1. Authenticated ingress: Supervisor peer `172.30.32.2`, role header `system-admin`, matching user ID, and **fresh** Home Assistant Core `config/auth/list` verification.
2. Explicit browser POST with **same-origin**, short-lived **one-use token** tied to the HA admin identity and exact typed `ΔΟΚΙΜΗ`. No GET ever writes.
3. One process permits at most one attempt. There is no scheduled or automatic action.
4. Fresh Core inventory guards against any residual name prefixed `Smart Pro QA TEMP NO LOGIN `.
5. `config/auth/create`: **one** non-owner local-only member of `system-admin`, random QA display name, **no credential**, no username or password.
6. Fresh `config/auth/list` verifies the returned ID, name, local-only, role, not owner, active, and no credentials.
7. `config/auth/delete` with **only** the just-created exact ID, plus fresh list readback to confirm it is gone. If validation fails after create, still attempt deletion.
8. Return only fixed, credential-free result codes. No HA user IDs, names, credentials or token are logged/sent to Portal.

## Failure caveat

Home Assistant user creation + deletion are separate API commands and **not an atomic transaction**. If the process dies, the Core connection drops, or the create reply is lost before reading the ID, an account record might remain. It has no login credentials, but it may still carry the administrator group. **Stop and inspect Settings → People → Users** for `Smart Pro QA TEMP NO LOGIN` before any subsequent attempt. Do not blindly remove other users.

No user creation in GET or any unattended path. No HA auth-provider username/password action is implemented. This QA proves write authority only; **it does not solve permanent Smart Pro access, secret storage, revocation, or Portal integration**.

## Rollout QA checkpoints

1. Upgrade 0.2.0 → 0.3.0 only in the test HA. Confirm the admin sees the new one-time form; **do not submit** until the assistant reviews the screenshot.
2. Non-admin `smartpro_qa_user` sees rejection and no form.
3. Only after the first checkpoints, submit once and verify result + user-list absence. Stop on errors.
4. Stop the QA app. Keep existing Smart Pro System 3.0.28, Managed Support 3.19.2, Tunnel, Portal unchanged.

## Static QA

Test runner: `python3 -m unittest discover -s tests -p 'test_access_*.py' -v`.
The repository-changes ZIP is **not** a Home Assistant install ZIP by itself.
