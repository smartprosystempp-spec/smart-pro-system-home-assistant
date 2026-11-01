# Smart Pro Customer Access — Stage 5 / Core Authority Readback

**Ημερομηνία:** 2026-11-01  
**QA addon:** `smart-pro-access-preflight` 0.2.0  
**Scope:** controlled read-only Home Assistant test, NOT account provisioning.

## Verified real HA baseline — Stage 4 (0.1.0)

| Account/test | Observed outcome |
|---|---|
| Existing Home Assistant admin | Recognized, PASS |
| `Smart Pro QA User` / `smartpro_qa_user` | Non-admin denied, PASS |

The QA user was created **only on the fresh test Home Assistant** with
Administrator OFF and Local access only ON. Keep for regression; do not record
its password in this repository or any QA report.

## Stage 5 read-only boundary

Stage 4 relied on Supervisor ingress identity/group headers. Stage 5 requires
**both** that ingress proof and an exact match against a fresh `config/auth/list`
Core WebSocket response from Home Assistant. The protected `SUPERVISOR_TOKEN` is
used locally inside the QA container and is never output. Names and credentials
from Core are discarded. Unknown, inactive, system-generated or non-admin
identities are denied; no fallback to ingress-only acceptance is permitted.

`homeassistant_api: true` is added **only** to the isolated QA 0.2.0 add-on
for the read-only probe; do not enable on Managed Support or expand
Portal/production command capabilities. Code must not send `config/auth/create`,
`config/auth/delete`, update or credential commands.

## Internal verification before live QA

- Python unit/integration and real localhost HTTP tests: see `QA-RESULTS.txt`
- No Docker/HA Supervisor live build was available internally
- Live 0.2.0 Core readback: **PENDING**
- Test production devices and existing add-ons: **DO NOT MODIFY**

## Next checkpoint

Open 0.2.0 as test HA administrator; expect dual validation. If `core_*`
failure is shown, stop and inspect the fixed reason code. Then verify the
normal QA user is denied without expanding account rights. No account creation
until independent authorization, consent, credential custody and revocation
security contracts are verified.
