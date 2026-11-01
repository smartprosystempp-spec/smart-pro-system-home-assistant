# Smart Pro Customer Access — Stage 7 / 0.3.1 origin compatibility correction

Date: 2026-11-01. Test-only release, never production.

## Live evidence

- QA 0.3.0 / real admin: confirmed against Supervisor Ingress and Home Assistant Core; displayed manual one-use action.
- QA 0.3.0 / `smartpro_qa_user`: denied, no action shown.
- First administrator POST: HTTP 403 `Invalid request origin`. Rejected before calling `run_qa_roundtrip`, meaning no user create/delete attempted in that HTTP request.

## Cause and correction

The original `same_origin` demanded `Origin` authority match application Host. In Supervisor Ingress, the browser sees the HA frontend origin while the proxied app can see an internal Host. That assumption can be false without indicating a cross-site attack.

0.3.1 accepts this mismatch only if modern browser Fetch Metadata supplies `Sec-Fetch-Site: same-origin`, while retaining a valid, non-null HTTP(S) Origin. Cross-site, same-site and missing/untrusted metadata with different Host fail closed. The independent Supervisor ingress peer check, identity headers, fresh admin Core readback, one-use 180s CSRF token, explicit typed approval, and one-process write limit remain.

New `POST /origin-check` does **not** consume approval, call a write handler, or create a user. It is offered in the admin-only page as an explicit read-only step before allowing any real account round-trip. Invalid-origin rejections now show a friendly nonsecret error page instead of unstyled raw text. No runtime/permissions changes to the other Smart Pro add-ons.

## Required field check

1. Update only the QA app to 0.3.1 in the test installation; no Publish Action.
2. With HA administrator, launch UI and click **Έλεγχος φόρμας χωρίς δημιουργία χρήστη** only.
3. Expect `origin_probe_passed_no_write`, and verify no `Smart Pro QA TEMP NO LOGIN` user exists.
4. Stop and collect screen if `origin_proof_rejected_no_write`, without sending token/cookies/ingress URLs.
5. Perform real user round-trip separately only after this checkpoint is accepted.

**Live 0.3.1 QA: PENDING.**
