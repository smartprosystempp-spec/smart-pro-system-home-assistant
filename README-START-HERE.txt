SMART PRO ACCESS PREFLIGHT — QA 0.3.0 (Stage 6)
================================================
Repository changed-files ZIP. NOT a standalone Home Assistant installer.

1) Windows: Extract All (do NOT upload a ZIP or its virtual folder).
2) GitHub repository ROOT: Upload exactly the extracted 3 directories
   docs/, smart-pro-access-preflight/, tests/ and the 2 QA text files.
   Preserve full paths and replace matching files; do not move app.py,
   Dockerfile, config.yaml or README.md into the repository root.
3) Do not run existing Publish Actions or touch the existing add-ons.
4) Test Home Assistant only: refresh store, update just the QA addon to 0.3.0.
5) Open as administrator; expect Core verification and an approval form.
6) STOP THERE. Do not type ΔΟΚΙΜΗ or submit until the screenshot is reviewed.
7) As non-admin user smartpro_qa_user, expect denial and NO approval form.
8) The subsequent single create/delete test must be separately authorized,
   and afterward Settings > People > Users MUST be inspected for orphans.

NEVER install into customer/production Home Assistant. No Portal changes.
No passwords, tokens, user IDs or ingress URLs should be shared in QA.
