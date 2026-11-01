# Smart Pro Customer Access — Stage 4 field preflight

**Release type:** changed-files-only for the existing GitHub repository. **Not** a completed end-user provisioning flow.

Scope: temporary read-only QA add-on `smart-pro-access-preflight` to validate trusted Home Assistant Ingress identity/group headers. No edits to main Smart Pro System, Managed Support, Tunnel, Portal or current production permissions.

Expected outcomes:
- Admin Home Assistant user -> eligible read-only display.
- Normal user -> blocked.
- Direct LAN request or missing/forged headers -> blocked.
- No creation, deletion, modification or transmission of any Home Assistant account or password.

Security rationale: Home Assistant Supervisor removes forged inbound identity/group headers, injects the authenticated user role and forwards ingress requests to an add-on from 172.30.32.2. Socket peer matching is mandatory, not `X-Forwarded-For` or a browser-supplied field. See [Home Assistant Ingress guide](https://contributors.home-assistant.io/apps/guides/ingress/) and [Supervisor implementation](https://github.com/home-assistant/supervisor/blob/main/supervisor/api/ingress.py).

No Home Assistant admin API token is given to this temporary QA add-on. We avoid any privileged operation until the user and installation ownership binding, one-time consent and full account lifecycle are ready.

**Next checkpoint after live QA PASS:** Add controlled, single-use consent flow in the primary Smart Pro System + Portal; implement admin user provision/revoke only after exact local Home Assistant administrator approval and explicit customer action. Must not reuse this read-only pilot result as consent.
