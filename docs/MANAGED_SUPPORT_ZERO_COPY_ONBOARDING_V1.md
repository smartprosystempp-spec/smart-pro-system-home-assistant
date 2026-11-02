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
