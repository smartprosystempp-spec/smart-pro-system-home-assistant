# Smart Pro Customer Access — Stage 8 / Safe Browser Ingress Metadata QA

- Version: 0.3.2
- Observed live 0.3.1: `origin_proof_rejected_no_write` from normal HTML form POST.
- This indicates no account write; origin metadata failed earlier than consent.
- Root cause is not fully established: Origin can be absent, `null`, or
  differ from internal proxy Host; Sec-Fetch-Site can be missing or different.
- Do not loosen the production account write boundary on assumptions.
- The entire active POST handler of 0.3.2 is diagnostic-only; POST / returns 405.
- `account_roundtrip.py` remains a source-only isolated lab module, excluded
  from the Docker image and not imported by runtime.
- New on-page controlled same-origin fetch probe with custom request header.
- Reports only sanitized classifications; no actual header values or PII.
- Next decision depends on actual browser metadata observed through trusted ingress.
- No changes to Smart Pro System / Managed Support / Tunnel / Portal.
