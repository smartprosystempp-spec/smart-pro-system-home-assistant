# Smart Pro Customer Access — Stage 11 / Credential Login Lab

Date: 2026-11-01. Runtime: `smart-pro-access-preflight` **0.5.0**. Test HA **ONLY**.

## Baseline from real HA screenshots

| Phase | Verified result |
|---|---|
| v0.2 | HA administrator Core confirmation PASS; `Smart Pro QA User` non-admin denied PASS |
| v0.3.3 | `qa_account_created_verified_deleted`; no QA TEMP user left |
| v0.4 | `qa_retained_admin_created_no_login`; persisted after QA add-on restart; `qa_retained_admin_revoked_verified`; normal users unchanged |

The old retained admin was revoked. `Smart Pro QA User` (username `smartpro_qa_user`) is the separate non-admin regression account. No passwords were captured in the project.

## v0.5.0 change

Adds an independently approved, local-only, non-owner admin `Smart Pro QA LOGIN LAB`, username `smartpro_qa_login_lab`, random 48-character URL-safe password; exact privileged commands are allow-listed. Password is returned ONCE to authenticated local admin browser after successful Core verification, not stored by QA app. Separate revoke deletes only unchanged lab user and verifies complete absence. Legacy non-login UI stops issuing approval tokens.

## Safe live QA order

1. Visual-only opening; no write. Verify account absent and admin role confirmed.
2. Authorize local-only QA credential creation once. Keep secret OUT of screenshots, files, tickets and chats.
3. Test local HA login using separate incognito session (do not modify HA configuration).
4. Revoke exact QA login account with second scoped consent; verify user removal and that new login with old secret fails.
5. Stop QA addon. Never use as customer enrollment or permanent Smart Pro access.

## Current limits

The credential-lab implementation has passed isolated tests, Python syntax, JS syntax and local HTTP negative/positive scenarios. It has **NOT** been run against a live Home Assistant yet. We have **NO** Smart Pro credential vault, no Portal integration, no remote desktop/managed access wiring. An interrupted provisioning operation could leave an account and requires controlled manual examination. No full production readiness claim.
