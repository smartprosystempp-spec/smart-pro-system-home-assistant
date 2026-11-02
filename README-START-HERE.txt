SMART PRO SYSTEM — Home Assistant Credential Handoff Stage 2
SOURCE OVERLAY FOR GITHUB MAIN — NOT A HOME ASSISTANT INSTALL ZIP

VERSION: Smart Pro System 3.0.29
BASE: GitHub main / Smart Pro System 3.0.28

This ZIP changes/creates exactly:
  smart-pro-system/run.sh
  smart-pro-system/Dockerfile
  smart-pro-system/config.yaml
  smart-pro-system/ha_credential_handoff_qa_agent.py (new)
  .github/workflows/publish-smart-pro-system.yml
  README-START-HERE.txt (documentation only, optional repo upload)

No changes to smart-pro-system/app.py, index.html, script.js, or existing Managed
Support, Tunnel, QA Access Preflight add-on, Portal pairing, subscriptions or
heartbeat code. The existing image is still published via GitHub Actions.

SAFETY: Opt-in `ha_credential_handoff_qa_enabled` is FALSE by default.
The worker only polls an explicitly queued Portal test with its EXISTING
Installation Token and sends fixed, fake username/password constants.
NO real Home Assistant user is created. NO real credentials are created, saved,
retrieved or delivered. NO password is obtained from Home Assistant.

INSTALLATION SEQUENCE, STOP AT FIRST CHECKPOINT:
1. Install Portal 3.6.395 first, check it displays Agent Synthetic subcard.
2. Upload this overlay to GitHub main, retaining all existing repository files;
   do not delete or replace whole folders. Commit.
3. GitHub Actions > Publish Smart Pro System image > Run workflow (main).
   Verify amd64+aarch64 build and manifest success.
4. In the TEST Home Assistant only, update Smart Pro System to 3.0.29. Do NOT
   uninstall the add-on and do NOT re-pair. Keep Managed Support unchanged.
5. Its Configuration option `ha_credential_handoff_qa_enabled`: switch to TRUE
   and save; restart ONLY Smart Pro System add-on if required.
6. Admin Portal > Installations > the same paired installation > Full Folder >
   Overview > Credential Handoff QA > 'Δοκιμή πραγματικής επικοινωνίας'
   > 'Έναρξη δοκιμαστικής αποστολής από Home Assistant' ONCE.
7. Refresh after ~20 seconds, expected AGENT_SYNTHETIC_RECEIVED with fixed FAKE
   username and password, and correct Installation ID.
8. Wait for separate guidance before acknowledge/cleanup.

STOP immediately if any UI displays REAL delivery enabled or any real secret.
Do not send passwords, tokens or entire local logs to ChatGPT.

This is SYNTHETIC transport testing only. Real credential handoff needs a
separate hardening milestone: end-to-end encryption, controlled one-time
reveal, local HA admin consent, durable anti-replay, correct identity and
lifecycle, fail-closed expiry and deletion with backup/key review.
