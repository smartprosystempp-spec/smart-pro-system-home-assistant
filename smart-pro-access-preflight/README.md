# Smart Pro Access Preflight — QA 0.6.0

**TEST HA ONLY — never customer production.** No new VPS, persistent Vault or background account creation.

## Manual one-time secure handoff (15 minutes)
1. Admin Portal > correct installation > secure receiver > Prepare. Only the WordPress administrator sees the one-time ticket.
2. On the matching QA Home Assistant open Smart Pro Access QA 0.6.0 **as verified HA administrator**.
3. Paste the full `ID-xxxxx:64hex` ticket and explicitly type `ΠΑΡΑΔΟΣΗ`. Submit **once**.
4. QA app verifies via HA Supervisor Ingress + fresh HA Core list and checks the Portal ticket and key *before* it creates a local-only QA administrator.
5. QA app creates `Smart Pro QA LOGIN LAB / smartpro_qa_login_lab` with real random password and seals it directly for Portal's X25519 public key using PyNaCl SealedBox. Plain password is NEVER written to disk, passed via browser or ordinary heartbeat, stored in QA logs or sent to ChatGPT.
6. After a successful handoff, Portal shows `ENCRYPTED_RECEIVED`. WP admin POST `Εμφάνιση κωδικού` decrypts into a no-store page; user copies it into their own secure password manager, then acknowledges & clears.
7. Test local login and, after completing QA, revoke the account via the distinct `ΔΙΑΓΡΑΦΗ` action.

On failed/ambiguous delivery **DO NOT REPEAT CREATE**. Inspect Admin Portal and Home Assistant users. Since the account may already exist, recover through the existing explicit revoke.

Security constraints: no generic remote privileged HA command, no HA password through regular Tool heartbeat, Portal owner manually arms scoped 15-minute ticket, no cross-add-on credential/file access. The one-time ticket is a sensitive bearer capability: never share, screenshot or log it.

The previous 0.5.0 free-standing password-reveal/create button is intentionally disabled for 0.6.0. Live release only after WordPress/PHP sodium and exact HA image QA.
