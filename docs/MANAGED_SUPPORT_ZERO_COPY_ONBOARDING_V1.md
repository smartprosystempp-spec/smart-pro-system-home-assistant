# Managed Support — Zero-Copy First Enrollment v1
Status: **design-only / no runtime authority** · 2026-11-02

## Current baseline
- QA5 / ID-28422 has Advanced Monthly ACTIVE (02/11/2026–02/12/2026); Managed Support 3.19.3 is STOPPED and unpaired. Preserve current state until a compatible release.
- Managed Support 3.19.3: stable POST action gate and graceful SIGTERM have passed no-identity HA testing. Legacy `/managed/pair` consumes a manual `SPM-` pairing code and stores private `/data/managed-identity.json`. This old form and endpoint remain locked.
- Existing Broker bootstrap, `.msh` ticket and agent verification require a *pre-existing* Managed identity; they are not zero-copy first enrollment.
- Smart Pro System's local managed-policy contract is non-secret, derived from Portal pairing and liveness. It is an authorization guard, not a new client identity credential.
- Portal 3.6.399 contains Home Assistant administrator credential handoff work, **separate** from MeshCentral Managed Support first-enrollment. Inspected code does not prove a Managed Support initial-enrollment writer.
- No authoritative current Broker plugin source has yet been located in the Home Assistant repository. Do not infer live first-enrollment endpoints from historical Broker QA.

## Proposed end-to-end flow
1. Customer or authorized Admin explicitly approves Managed Support enrollment for the exact Installation ID. Portal verifies current Advanced/Complete entitlement, owner/admin authority, current Smart Pro System device binding/liveness, no duplicate or revoked/conflicted Managed enrollment.
2. Broker issues one short-lived, installation-scoped, single-use pending enrollment authorization. Audit opaque request ID, actor and state. Do not grant technician Web/Terminal/Files/Desktop.
3. Already-paired Smart Pro System receives the signed activation intent through its existing authenticated channel; hands off only a constrained opaque claim authorization to Managed Support through private atomic local storage. No `node_secret`, `.msh` or customer password is placed in shared policy, Portal HTML, email or logs.
4. Managed Support checks exact local policy installation ID, binding and expiry, then claims the authorization from Broker over HTTPS. Broker atomically allows at most one Managed node identity for the bound installation.
5. Only Managed Support receives the new `node_id`/`node_secret` via TLS, stores them with existing private atomic `save_identity()`, verifies Broker heartbeat and then uses the existing controlled MeshAgent settings/lease/run chain. New active-session capabilities remain OFF.
6. Portal exposes read-only WAITING / VERIFIED / DENIED status without secrets.

## Security and recovery
- No `/managed/pair` reactivation, manual pairing code, unauthorized local source, shared durable credentials or broad network opening.
- Enrollment fails closed for stale pairing, invalid entitlement *at enrollment*, missing consent, device/installation mismatch, replay, expired claim or offline Broker. Existing relationship **survives subscription expiration**; only explicit revocation changes it.
- Lost Broker claim response or client disk failure must not create a second node. Require idempotent recovery or admin-controlled reconciliation before any write release.
- One existing Managed identity must never be silently overwritten; revoked identity requires separate explicit recovery. No MeshCentral permissions or technician sessions added.
- Keep installation ID and device fingerprint bound, one-time TTL, per-installation lock, audit; logs contain reason codes and opaque hints, never raw tokens.

## Implementation/release sequence
A. Review **exact current Broker source + installed version**. Define safe request/claim/ack/deny/reconciliation routes and tests (admin/owner/entitlement/auth/replay/concurrency).
B. Implement Portal authorization and status on Broker-supported contract. No customer-visible activation button until permissions and compatibility tests pass.
C. Implement authenticated Smart Pro System one-shot handoff with exact binding; signed intent only, no raw node credentials.
D. Implement Managed Support consumer, one-time claim, private identity persistence, Broker readback; keep legacy mutation POSTs locked. Existing MeshAgent runtime untouched.
E. Release compatible versions together on QA5 and run **one** approved end-to-end positive onboarding test, plus isolated negative and idempotency tests. Do not alter other QA VMs.

## Acceptance and exclusions
- Pass requires Portal approval → device handoff → single Broker claim → one persisted Managed identity → stable online MeshAgent → Portal health, all without copying credentials.
- Until actual Broker source is reviewed, **no write code, image build, plugin update, pairing or QA5 startup** is authorized by this document.
- Not in scope: Home Assistant admin user creation, subscription modifications, backup, External URL, Tunnel, MeshCentral technician grants or wider access.

## Source review — exact Broker 0.60.32 (2026-11-02)
User supplied complete WordPress plugin ZIP `smart-pro-remote-session-broker-0.60.32-diagnostic-renewal-noise-gate(1).zip` (SHA-256 `b0dd5fea23957d349af493b6e610be2947840f926d7c7e5df26aa0c33be35690`).
- Broker already implements `SPRSB_Managed::issue_pairing()` (15-minute single-use `SPM-` code) and `SPRSB_Managed::consume_pairing()`, which returns a private `SPMN-` node identifier and `SPMS-` secret to the client. Do **not** duplicate these identity foundations.
- Current issuance is exposed through an Admin-only action; the Managed client's legacy pairing form remains locked. To achieve *zero-copy*, add a new explicitly authorized, exact-installation device handoff while keeping the legacy UI disabled.
- Portal 3.6.399 already authenticates Tools `/heartbeat` with the installation token; its response has a control-plane section. **No existing Managed first-enrollment activation intent was found**. Device delivery requires a separate signed, one-time binding; the existing installation token alone is not authorization to create a Managed account.
- No automatic retry after an unknown Broker-commit/client-response outcome. Existing `consume_pairing` has a one-time consumption race guard but does not implement durable client response recovery. A safe reconciliation or idempotency contract must be designed before live activation.
- An internal-only Broker 0.60.33 **readiness foundation** has been prepared offline (no REST route/POST handler). Its admission evaluator gates canonical installation binding, Portal pairing, fresh Tools heartbeat, active paid Managed entitlement, zero previous Managed nodes (including revoked), and zero pending manual pairings; database read failure is fail-closed. 16 isolated checks plus all PHP syntax checks PASS. This staging ZIP must **not** be installed until a full coordinated release exists.

### Coordinated release gate
Do not ship an isolated Broker or Managed Support build for this feature. The planned first live QA on ID-28422 requires the compatible Broker, Portal, Smart Pro System and Managed Support components, approved explicit consent, and a single audit-backed enrollment claim. Existing 3.19.3 stays stopped.

## Isolated Broker 0.60.34 reservation ledger (2026-11-02)
- Offline-only follow-up to 0.60.33. New dedicated SQL table with a permanent UNIQUE installation reference plus UNIQUE opaque non-bearer request ID and an expiry; managed-schema 11 → 12 **only in staged artifact**.
- Internal `reserve_admin_approval()` checks exact typed Installation ID, logged-in privileged operator, scoped WP nonce, 64-hex trusted device-binding digest and live admission readiness. A second request is denied even when the first has expired; reconcile deliberately remains a separately authorized future operation.
- Data stores only the operator/consent digest, bounded request metadata and device-binding hash: no node secret, SPM pairing token, Home Assistant credential, `.msh`, Managed permission or API token.
- 22/22 isolated ledger tests PASS and all Broker PHP files lint PASS, single-root ZIP integrity PASS.
- **The reservation is not an identity claim, and does not start provisioning.** No route or UI calls the method; no database migration has occurred on any installation. Package is INTERNAL / DO NOT INSTALL.
- Remaining critical work: signed Portal approval transport, bound client handoff and an atomic Broker identity claim with lost-response reconciliation; previous real-client tests must not be repeated before a coordinated release.

## Internal Broker 0.60.35 — server-derived pairing binding + atomic claim lock
- QA source artifact: `smart-pro-remote-session-broker-0.60.35-zero-copy-atomic-claim-lock-INTERNAL-DO-NOT-INSTALL.zip`, SHA-256 `421ab6654396fb7c58599326e7bbb4b2ffacc3bd2a5a57971f808a8f003ba889`.
- Important improvement over 0.60.34: the reservation's device-binding digest is **computed server-side** from the current canonical Portal pairing token lookup/hash; callers can no longer choose arbitrary SHA-256 fingerprints. Rotation of Portal pairing invalidates old claims.
- Adds an **unwired** `lock_first_claim()` internal method: exact installation/request ID, current Portal pairing digest, matching server-signed attestation, unexpired approval, fresh entitlement/Tools state, and atomic SQL CAS from `pending_handoff` to `claim_locked`. Unknown outcomes and repetitions remain fail-closed; no automatic retries.
- Offline PHP lint: all 27 plugin PHP files PASS; isolated lock-gate tests 39/39 PASS; ZIP single-root integrity PASS. Broker REST, node identity writers, MeshCentral and other services unchanged; no data migration beyond the prior internal reservation schema.
- **Not sufficient for a production activation:** the signed attestation alone is NOT a device authentication proof. A dedicated authenticated Portal-to-Tools handoff and independent client proof must exist before exposing any new REST claim route or issuing an identity. No public signer, client secret, claim endpoint, identity creation or runtime activation is included.
