# Smart Pro Customer Access — Stage 9 / Browser-Proven Controlled Roundtrip

Date: 2026-11-01. QA App: 0.3.3.

## Evidence

Live 0.3.2 metadata test: `request_metadata_observed_no_write`; `origin: valid`; `origin_host: same`; `custom_header: yes`; `fetch_site: missing`.

**Interpretation:** The custom fetch request supplies a browser Origin matching the proxy Host, even where Sec-Fetch-Site is stripped. Browser HTML form origin behavior differs. Do not infer write authority from metadata alone.

## Change

- Strict Origin==Host (validated origin URL), reject duplicate origin/host/action headers and hostile Sec-Fetch-Site values when present; fetch-site may be missing.
- Protected JSON fetch+special header for account-changing request; no ordinary HTML POST path.
- Admin/Core proof, one-use 180 second CSRF tied to the current HA admin ID and typed approval, single process attempt and no auto-start.
- Existing QA account prefix scan, credentialless create, verify, delete, verify absent; explicit manual follow-up when Core response is uncertain.
- No Portal writes, no regular add-on changes, no publish workflow.

## Live checkpoints

0) Install 0.3.3 on TEST HA only; initially read-only green probe. STOP without blue write.
1) On explicit approval, one admin-initiated roundtrip; record only fixed response code.
2) Regardless of response, check Users screen for `Smart Pro QA TEMP NO LOGIN …` leftovers; never retry blindly.
3) Confirm normal user denied. After PASS, stop QA app.

This proves *only* Core authority to create and delete a credentialless account. It does not prove account login, token custody, Portal enrollment, revocation in production, or support-grant authorization.
