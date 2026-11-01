SMART PRO CUSTOMER ACCESS — TEST-ONLY QA UPDATE 0.3.1
====================================================
This is a changed-files ZIP to merge at the ROOT of the existing GitHub repo.
Extract before uploading. Preserve full paths. DO NOT replace root README.md,
repository.yaml or change any of the 3 existing Smart Pro add-ons.

Change: Home Assistant Ingress browser origin compatibility + read-only
POST probe, independent of the real account create/delete.

Run NO publish action. After updating the TEST HA QA app, first click ONLY
"1. Έλεγχος φόρμας χωρίς δημιουργία χρήστη" as admin.
Expected: origin_probe_passed_no_write; no account is created.
Do NOT type ΔΟΚΙΜΗ or submit account creation until separately agreed.
See smart-pro-access-preflight/README.md and docs/SMART_PRO_CUSTOMER_ACCESS_QA_STAGE7.md.
