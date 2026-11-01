# Smart Pro System — Customer Managed Access Enrollment (Foundation v0.1)

Status: **DESIGN / READ-ONLY — NO CUSTOMER ACCOUNT PROVISIONING**  
Date: 2026-11-01  
Target repository: the *whole* Smart Pro System Home Assistant add-on family.

## Customer goal

A subscriber who has already linked Smart Pro System with the Customer Portal can finish the separate Smart Pro technician-access setup with a simple guided approval. The customer must not search Home Assistant's Users settings or send their own password to Smart Pro.

**24/7 health monitoring is independent of interactive administrator access.** An online Managed Support node is not an active technician grant.

## Verified starting point (main branch)

- `smart-pro-system/config.yaml` — Smart Pro System **3.0.28**, with `homeassistant_api: true`; the existing runtime uses the Home Assistant Supervisor Core API proxy and a scoped `SUPERVISOR_TOKEN`.
- `smart-pro-managed-support/config.yaml` — Managed Support **3.19.2**, *without* `homeassistant_api`; remains responsible for the separately controlled remote-support connection.
- `smart-pro-tunnel/` and the existing subscription, backup, pairing, Managed identity, Portal command capability lists, and remote permission enforcement stay unchanged.
- Home Assistant's official WebSocket commands `config/auth/create` and `config/auth_provider/homeassistant/create` are protected by administrator checks. The official add-on guide says `homeassistant_api: true` and its Supervisor proxy act with administrator privileges; therefore the main add-on already has sensitive authority which must never be exposed through a browser endpoint.

References:
- https://developers.home-assistant.io/docs/add-ons/communication/ (may redirect to current apps guide)
- https://developers.home-assistant.io/docs/add-ons/configuration/ (may redirect to current apps guide)
- https://github.com/home-assistant/core/blob/dev/homeassistant/components/config/auth.py
- https://github.com/home-assistant/core/blob/dev/homeassistant/components/config/auth_provider_homeassistant.py

## Required safety gates — MUST ALL be verified before any account-write code is activated

1. **Portal identity**: validated logged-in customer, fresh strong 2FA, current ownership of the exact subscribed installation, and explicit consent for a *separate* Smart Pro support administrator. A paired installation alone is not consent.
2. **Local Home Assistant owner/admin approval**: prove the person approving is authorized to manage users in **that specific Home Assistant installation**. A Portal-only customer click, a browser-supplied `true` flag, or an existing local technician PIN is NOT sufficient evidence. The actual supported proof path (Home Assistant authenticated session / assisted approval) must be tested before implementation.
3. **Bound, one-time request**: exact installation and device binding; named purpose; short expiry; unique request ID and replay rejection; server-side verification. No arbitrary account name, user ID, privilege, password or raw Home Assistant API command may be accepted from the browser or Portal.
4. **Safe account lifecycle**: new *non-owner* account only; never change an existing account, owner, or password. Check for a prior Smart Pro account, duplicate requests and partial success; safely recover or stop without unexpected user creation. Distinguish an HA user from a username/password credential.
5. **Credential policy not yet decided**: do not transfer a password to the Portal or store it in messages, logs, telemetry, browser state, tickets or command acknowledgements. Decide whether a permanent HA password is necessary at all; prefer existing controlled Managed access and local credential custody where feasible. If a server-side secret vault is truly required, specify encryption keys, access controls, rotation, backup/restore, incident response and revocation *before* delivery.
6. **Revoke and audit**: customer can clearly revoke Smart Pro access, with independent technician-session/grant cancellation, complete audit and no unintended interruption of normal health monitoring. Portal suspension or disconnect must fail safely.
7. **No public write endpoint**: no new user-creation capability through the add-on's current general-purpose browser API. Any future local action needs its own authenticated and owner-approved security boundary. The existing local technician PIN flow must NOT be reused as proof of customer consent.

## Security blocker found in the current main add-on

In `smart-pro-system/app.py`, the existing `/api/verify_pin` handler compares against a hard-coded PIN, and the HTTP server binds on all interfaces (`('', PORT)` with `host_network: true`). Some existing browser API actions also have inconsistent authorization checks.

This does **not** establish Internet exposure, but it means the current local browser API is unsuitable for high-privilege account-creation functions. Review and address this *separately, compatibility-first*, before the provisioning interface is connected. Do not break the Technician Center, monitoring, Portal pairing or existing commands merely to add enrollment.

## Project stages

**Stage 0 — this branch, read-only:** record authority and safety requirements; add tests that freeze the safe baseline. No runtime, version or production changes.

**Stage 1 — isolated guarded preflight:** identify/prove the authenticated Home Assistant administrator confirmation mechanism and protected communication path. Read-only checks only, with no new users and no credential transfer.

**Stage 2 — dedicated test installation:** explicit authorized consent, exactly one test non-owner support-admin user, successful credential setup, duplicate rejection and full deletion/revocation. Must not act on a customer installation.

**Stage 3 — Portal UX and credential decision:** guided activation and status, purpose and withdrawal, secure local/server custody as approved. Add Portal code only after the exact security contract is validated.

**Stage 4 — release/QA:** grouped updates of affected source, changelog, documentation, build workflows and version tags. Test on both supported architectures, then controlled production approval. Preserve pairing, monitoring, MeshCentral and subscription behavior.

## Release discipline

Changes must be planned against the entire repository, not just `smart-pro-managed-support/`. Update only the actually affected add-ons and their relevant metadata, README/changelog, tests, image workflow tags, Portal counterpart and QA notes. **Do not bump or rebuild unrelated add-ons by default.** No automatic installation or merge to `main`.
