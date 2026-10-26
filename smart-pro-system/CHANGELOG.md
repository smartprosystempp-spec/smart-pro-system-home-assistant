## 3.0.14 — Managed Backup Controlled Presigned Primary Upload v1
- Adds exact-bound short-lived presigned PUT/HEAD/GET executor for one verified local backup.
- Adds capability `primary_presigned_upload_execute`.
- Validates installation/node/policy/job/object/TTL and Control Plane HMAC before network I/O.
- Upload uses Content-MD5, signed Object Lock GOVERNANCE headers and If-None-Match `*`.
- Performs HEAD retention verification and full GET read-back SHA-256 verification.
- Raw OVH credentials are never received or stored on-device.
- Replication/delete/restore remain OFF.

## 3.0.13 — Managed Backup Presigned Source Handoff Foundation v1
- Managed Backup storage handoff v2 verifies the existing local backup source without requiring OVH/S3 credentials in Smart Pro System.
- Adds capability `primary_presigned_upload`; no presigned URL execution or S3 write is enabled in this release.
- Legacy local-credential upload implementation remains present but receives no new authority from this release.

## 3.0.12 — Tunnel Recovery Diagnostic Cleanup

- Removes the temporary read-only `/api/tunnel_store_diagnostic` endpoint introduced only for 3.0.11 QA.
- Removes the diagnostic scheduler pause and restores normal automatic Smart Pro Tunnel companion recovery.
- Preserves the live-proven Supervisor Store repository-slug/source matching and `version_latest` handling from 3.0.9–3.0.10.
- Keeps Portal pairing, subscription, Guardian, Smart Pro Tunnel 0.1.7, Managed Support, Managed Backup and signed Control Plane behavior unchanged.
- Does not alter the persisted recovery history semantics; runtime `connected/listening/reachable` remains authoritative for current Tunnel health.

## 3.0.11 — Tunnel Store Live Contract Diagnostic

- Adds one bounded read-only `/api/tunnel_store_diagnostic` endpoint for replacement QA.
- Exposes only sanitized Store candidate/repository/version/stage/availability metadata needed to isolate `store_match_missing`; no Supervisor token, app options, credentials or key material are exposed.
- Temporarily pauses automatic Tunnel companion recovery in this diagnostic build so no install/start mutation can occur while inspecting the live Store contract.
- Keeps Portal, subscription, Guardian, Tunnel 0.1.7, Managed Support and signed Control Plane logic unchanged.

## 3.0.10 — Tunnel Store Repository Contract Fix

- Διορθώνει το replacement Tunnel Store discovery ώστε το app `repository` να αντιμετωπίζεται ως Supervisor repository slug, όχι ως URL.
- Επαληθεύει fail-closed το repository slug μέσω του Store `repositories[].source` απέναντι στο επίσημο tokenless Smart Pro GitHub repository πριν από οποιοδήποτε install.
- Διατηρεί το 3.0.9 `version_latest` fix και όλο το υπάρχον signed Control Plane / zero-copy provisioning αμετάβλητο.

## 3.0.9 — Tunnel Store Discovery Version Contract Fix

- Fixes replacement Tunnel recovery discovery for uninstalled Store apps.
- Uses Supervisor `version_latest` as the authoritative available Store version, with `version` only as compatibility fallback.
- Keeps exact name/slug/repository validation, fail-closed discovery, install/start ownership boundaries and signed Control Plane authority unchanged.
- No Portal, Tunnel, Managed Support, subscription, provisioning or schema changes.

## 3.0.8 — Replacement Companion Recovery / Tunnel Pilot

- Adds a fail-closed replacement-device recovery pilot for the official Smart Pro Tunnel companion app.
- Requires verified Portal pairing plus a fresh effective Managed External URL entitlement before any recovery action is scheduled.
- Discovers exactly one `Smart Pro Tunnel` entry from the Home Assistant store, requires the official tokenless Smart Pro repository and version 0.1.7 or newer, then installs it through the Supervisor Store API only when absent.
- Performs one initial start with the Tunnel defaults (`enabled=false`) so the Tunnel creates its own persistent WireGuard identity and publishes public-only enrollment material.
- Does not generate/copy/read the Tunnel private key, does not configure WireGuard/Gateway/DNS/public ingress and does not bypass the existing signed Control Plane.
- Adds bounded sanitized recovery state under `smart_pro_tunnel_runtime.recovery` for QA/diagnostics and a 15-minute fail-backoff after recovery errors.
- Keeps Managed Support automatic recovery out of scope for this pilot.

## 3.0.7 — HA Scoped Credential Unification

- Uses the Home Assistant OS/Supervisor-scoped `SUPERVISOR_TOKEN` as the default Core API credential when available.
- Keeps the manually configured Home Assistant long-lived token only as a compatibility fallback.
- Removes legacy manual-token gates from Guardian, Home Assistant Diagnostics, Managed Backup local readiness, Watchdog safe test, Smart Updates, Vacation Mode and entity loading.
- Keeps `homeassistant_api: true`, Portal pairing, subscription semantics, Managed Support, Smart Pro Tunnel and External URL runtime authority unchanged.
- Preserves the existing Managed Backup heartbeat field name `ha_token_configured` for contract compatibility; its boolean now represents effective HA API credential availability.

## 3.0.6 — External URL Persisted State Idempotency Fix

- Makes the Managed External URL Portal-state normalizer idempotent across raw heartbeat and already-normalized persisted shapes.
- Preserves standalone status/cycle/dates, package eligibility, publication status, PUBLIC READY and hostname when `external_access_portal` is read back for `/api/portal_status`.
- Fixes the 3.0.5 double-normalization regression where top-level eligibility survived but standalone/publication detail fell back to `not_configured` / `unknown`.
- Does not change Portal contracts, Trial/package semantics, Tunnel/runtime authority, provisioning, DNS, pairing, credentials or database schema.

## 3.0.5 — External URL Customer Heartbeat Compatibility Bridge

- Consumes the Portal 3.6.294 customer-safe `external_access_customer` heartbeat bridge as authoritative presentation state.
- Adds backward-compatible fallback to legacy top-level External Access `eligible` / `eligibility_source` fields.
- Keeps Tunnel runtime and Gateway observation handling independent from commercial entitlement/publication presentation.
- Does not grant runtime authority, start/stop services, change DNS, or expose credentials.

## 3.0.4 — External URL Heartbeat Synchronization Hotfix

- Consumes and persists durable Portal-owned standalone entitlement/publication presentation state.
- Displays `PUBLIC READY` and the public URL independently from the short-lived Gateway observation freshness window.
- Adds pairing-time External URL state persistence; existing heartbeat persistence remains intact.
- Keeps provisioning/runtime authority exclusively on the signed Control Plane and exposes no new secrets.
- Preserves the 3.0.3 Trial/standalone semantics and real Tunnel runtime presentation.

## 3.0.3 — Standalone / Trial Semantics & Runtime Truth

- Διορθώνει το customer mode ώστε Trial, paid subscription και standalone υπηρεσία να είναι διαφορετικές έννοιες.
- Εμφανίζει «Δοκιμαστική εγκατάσταση» στο Trial και «Συνδρομητική εγκατάσταση» όταν υπάρχει πραγματικό Care/Advanced/Complete relationship.
- Διαχωρίζει package inclusion από τρέχουσα service access κατάσταση για Managed Support.
- Διαβάζει το πραγματικό Smart Pro Tunnel runtime-status contract και δεν ταυτίζει πλέον το running add-on process με ενεργό WireGuard tunnel.
- Προσθέτει read-only Managed External URL entitlement/provisioning παρουσίαση από το Portal χωρίς να δίνει runtime authority στο UI.
- Βελτιώνει Guardian/Smart Updates και local-backup customer wording χωρίς αλλαγή στα security gates.
- Ολοκληρώνει τη version consistency του pre-built Smart Pro System 3.0.3.

## 3.0.1 — Unpaired State Semantics

- Fixes the first-run/unpaired UI so it never describes the installation as connected or subscription-blocked before Portal pairing.
- Support CTA now says that support becomes available after Portal connection instead of implying an inactive subscription.
- Guardian status now shows “Μετά τη σύνδεση με το Portal” while unpaired.
- Replaces false-positive “all online / batteries OK” wording with observation-safe local-health wording.
- Adds neutral informational styling for the unpaired health banner.
- No pairing, Portal contract, subscription, Guardian policy, Managed Support, Tunnel, Backup or External URL runtime changes.

## 3.0.0 — Smart Pro System vNext Foundation

- Starts the customer-facing **Smart Pro System** generation while preserving the technical slug `smart_pro_tools`.
- Replaces the old Tools-first landing screen with a customer-first installation dashboard.
- Introduces explicit presentation states for unpaired, standalone/one-off, and subscribed installations.
- Adds compact service visibility for Managed Support entitlement/runtime, Smart Pro Tunnel runtime, Managed Backup state, and Managed External URL state.
- Adds sanitized customer-facing Backup and External URL summaries to the local `portal_status` endpoint; no new mutation authority is introduced.
- Keeps the verified 2.4.58 Portal pairing/sync, Guardian, Control Plane, Managed Backup agent, External Access agent and runtime-detection foundations.
- Keeps all existing secrets server-side and does not add any secret to the browser response.
- Smart Pro Tunnel remains 0.1.6 and unchanged in this repository checkpoint.
- Technician static-gate replacement, automatic companion installation, replacement-device flow and zero-copy credential provisioning remain future vNext milestones.

## 2.4.58 — Smart Pro Tunnel Runtime Visibility v1

- Adds a separate read-only `Smart Pro Tunnel runtime` line to the Smart Pro Tools subscription card.
- Uses the existing Supervisor `/addons` inventory to report only installed/running/version/update state for the dedicated Smart Pro Tunnel add-on.
- Runtime states are explicit: running, installed/stopped, error, installed/unknown, not installed or unavailable.
- Does not install/start/stop/reconfigure Smart Pro Tunnel and never reads or exposes Tunnel key material.
- Does not change Managed External URL authority, pairing, subscription/wallet, Guardian, Managed Support, Managed Backup, MeshCentral or Control Plane behavior.
- Smart Pro Tunnel 0.1.6 remains byte-identical.

## 2.4.57 — Managed Support Entitlement / Runtime Clarity v1

- Splits the customer-facing Smart Pro Tools subscription card into two distinct read-only concepts: package entitlement and installed Managed Support runtime.
- `Δικαίωμα Managed Support` now reads the authoritative Portal entitlement instead of reusing the local managed-policy relationship gate.
- Adds a read-only Supervisor `/addons` probe for the dedicated Smart Pro Managed Support add-on and reports only installed/running/version/update state; no options, secrets or device identity are exposed.
- Runtime states are fail-closed and explicit: running, installed/stopped, error, installed/unknown, not installed or unavailable.
- Keeps the existing `managed_policy` contract unchanged for compatibility with Managed Support.
- Does not install/start/stop/reconfigure Managed Support, MeshCentral or Smart Pro Tunnel and does not change pairing, subscription, wallet, Guardian, Managed Backup, External URL or Control Plane authority.
- Smart Pro Tunnel 0.1.6 remains byte-identical.

## 2.4.56 — Trial State & Portal Sync UI v1

- Treats Portal `trial` as an onboarding/presentation state, never as a paid package or paid-runtime entitlement.
- Forces Guardian, Smart Updates, normal support-request and other paid entitlement gates fail-closed during Trial while preserving pairing and heartbeat.
- Shows a dedicated `ΔΟΚΙΜΑΣΤΙΚΗ ΠΕΡΙΟΔΟΣ` compact badge with the authoritative Portal Trial expiry/countdown instead of `Χωρίς πακέτο / --`.
- Distinguishes `Δεν έχει επιλεγεί πληρωμένο πακέτο` from the active Trial state in the Portal subscription panel.
- Replaces the misleading active-monitoring success banner during Trial with neutral Portal-sync wording.
- Cleans the pre-pairing presentation so a fresh installation shows `ΧΩΡΙΣ ΣΥΝΔΕΣΗ` and no longer runs the legacy local subscription-status writer once the Portal status endpoint is available.
- Makes no change to pairing identity, heartbeat transport, paid subscription arithmetic, wallet, Managed Backup, External URL or Smart Pro Tunnel. Tunnel 0.1.6 remains byte-identical.

## 2.4.55 — Managed Backup Sequential Daily Cycle Runtime

- Allows a new signed Managed Backup local job only after the previous local cycle reached a terminal state.
- A previous `local_verified` cycle must also have a matching `primary_verified` upload before the next daily job can start.
- Keeps the local backup and primary upload envelopes short-lived, exact-bound and replay-protected; no persistent runtime authority is granted.
- Reuses the live-verified OVH Milan S3 upload, Object Lock GOVERNANCE retention and full read-back SHA-256 verification from 2.4.54.
- Does not enable replication, delete or restore execution. Smart Pro Tunnel remains 0.1.6 byte-identical.

## 2.4.54 — Managed Backup S3 Preflight & Safe Error Classification

- Adds a read-only S3 `ListObjectsV2(MaxKeys=1)` preflight before downloading the local Home Assistant backup for a controlled primary upload.
- Fails fast on endpoint, credential or bucket-policy problems without creating an object or touching the verified local backup.
- Replaces path-truncated upload exceptions with bounded credential-safe S3 result codes such as `s3_accessdenied_put_object` or `s3_invalidaccesskeyid_list_objects`.
- Preserves the existing exact OVH Milan target, Object Lock GOVERNANCE retention, full object read-back SHA-256 verification and retry semantics.
- No Portal, Tunnel, subscription, scheduler, replication, delete or restore authority change.

## 2.4.53 — Managed Backup Supervisor Inventory Transport Hotfix

- Moves Managed Backup `/backups/info` inventory reads from the legacy Home Assistant Core WebSocket `supervisor/api` proxy to the supported direct Supervisor REST API using the add-on-scoped `SUPERVISOR_TOKEN`.
- Reuses the existing `_supervisor_api_json()` fail-closed transport and adds only read-only `GET /backups/info` to its exact allow-list.
- Fixes `websocket_command_failed` / `source_backup_inventory_verify_failed` on current Home Assistant while preserving the existing local backup job identity and OVH primary-upload contract.
- No new permissions, no Portal/Gateway/Tunnel change, no upload execution by merely upgrading, and no credential exposure.

## 2.4.52 — Managed Backup OVH Primary Upload v1
- Adds one controlled `primary_storage_upload` capability for the already verified local Managed Backup job.
- Downloads the exact local Home Assistant backup through the authenticated Supervisor backup download endpoint only after a signed Portal upload job is received.
- Uploads only to the exact OVHcloud Milan 3-AZ S3 target `smartpro-managed-backup-primary-mil`.
- Keeps S3 Access Key / Secret Key local in Home Assistant add-on options; credentials are never sent to Portal or heartbeat.
- Applies per-object Object Lock GOVERNANCE retention from the verified package policy (Advanced 7d / Complete 30d).
- Performs full S3 read-back SHA-256 verification before reporting `primary_verified`.
- Does not enable recurring scheduling, replication, delete or restore execution.

## 2.4.51 — Managed External URL Home Assistant core-target discovery
- Extends the direct Supervisor transport to the read-only `/core/info` endpoint.
- Resolves the exact internal Home Assistant Core IPv4/port/SSL metadata at command execution time instead of assuming `homeassistant:8123`.
- Passes only the sanitized internal target host/port/SSL flag into Smart Pro Tunnel options; no Supervisor token or Home Assistant credential leaves Smart Pro Tools.
- Requires Smart Pro Tunnel 0.1.6 before applying the private-path command.
- Keeps DNS, Caddy, public-route and customer URL authority OFF.

## 2.4.50 — Managed External URL direct Supervisor API transport fix
- Replaces the blocked Home Assistant Core WebSocket `supervisor/api` transport with the supported direct Supervisor REST API at `http://supervisor/`.
- Adds `hassio_api: true` and the minimum Supervisor role that permits installed add-on inventory plus options/start/restart operations: `hassio_role: manager`.
- Uses only the container-scoped `SUPERVISOR_TOKEN`; the token is never logged, rendered, persisted by Smart Pro Tools or sent to the Portal.
- The direct API helper is endpoint-whitelisted to `/supervisor/info`, `/addons`, and the exact installed Tunnel add-on info/options/start/restart endpoints required by this milestone.
- Migrates Supervisor/Add-on aggregate diagnostics to the same direct API path so live QA can distinguish runtime readiness without the blocked WebSocket proxy.
- Leaves Smart Pro Tunnel 0.1.5 byte-identical and makes no DNS, Caddy, public-route or customer URL mutation available.

## 2.4.49 — Managed External URL Supervisor add-on list normalization hotfix
- Fixes the private-path Supervisor bridge to accept the `/addons` WebSocket result in either supported normalized shape: `{addons:[...]}` or a direct add-on list.
- Reuses the already-proven normalization semantics from the existing read-only Supervisor diagnostics collector.
- Resolves the fail-closed `external_url_supervisor_addons_unavailable` seen before Smart Pro Tunnel discovery/options/start.
- Does not change Tunnel identity, private key handling, Gateway WireGuard state, DNS, Caddy, public-route or customer URL authority.
- Smart Pro Tunnel remains 0.1.5 byte-identical.

## 2.4.48 — Managed External URL options-loader recovery hotfix
- Fixes the controlled Tunnel Supervisor bridge to read the Home Assistant token through the existing `load_addon_options()` helper instead of the nonexistent `load_options()` symbol.
- Fixes the same latent fallback reference in the External Access heartbeat snapshot.
- Prevents the Portal heartbeat worker thread from crashing before the Tunnel options/start call during the private-path recovery command.
- Does not change Tunnel identity, WireGuard key material, Gateway, DNS, Caddy, public-route or customer URL authority.
- Smart Pro Tunnel remains 0.1.5 byte-identical.

## 2.4.47 — Managed External URL Tunnel enrollment validity hotfix
- Fixes the private-path Supervisor bridge precondition by marking the already validated local Tunnel enrollment snapshot as `valid: true`.
- Keeps the 2.4.46 public-key SHA-256 binding and exact fail-closed identity comparison unchanged.
- Resolves the remaining false `external_url_tunnel_identity_mismatch` before Tunnel options/start are applied.
- Does not expose private key material and does not change Gateway, DNS, Caddy, public-route or customer URL authority.
- Smart Pro Tunnel remains 0.1.5 byte-identical.

## 2.4.46 — Managed External URL Tunnel identity hash hotfix
- Fixes the local Tunnel enrollment snapshot so it exposes the SHA-256 of the already-validated public WireGuard key to the signed private-path runtime bridge.
- Resolves the fail-closed `external_url_tunnel_identity_mismatch` seen before Supervisor options/start were applied.
- Does not expose the private key and does not change Gateway, DNS, Caddy, public-route or customer URL authority.
- Smart Pro Tunnel remains 0.1.5 unchanged.

## 2.4.45 — Managed External URL private-path runtime bridge
- Adds signed Control Plane capability external_url_tunnel_configure_start.
- Uses Supervisor API via the authenticated Home Assistant WebSocket bridge to configure/start Smart Pro Tunnel.
- Reads safe Tunnel runtime status from shared storage; no private key is exposed.

# 2.4.44 — Home Assistant Internal API Transport Compatibility Hotfix

- Prefers the official Supervisor Core API/WebSocket proxy when the scoped `SUPERVISOR_TOKEN` is available.
- Adds `homeassistant_api: true` so new Home Assistant OS installations can reach Core without depending on the direct `homeassistant:8123` route.
- Keeps the existing configured Home Assistant Long-Lived Access Token and direct Core route as a backward-compatible fallback for older installations.
- Changes no Portal pairing, External URL entitlement, Tunnel enrollment, Gateway observation or write authority.
- Does not expose or log either Home Assistant credential.

# 2.4.43 — Managed External URL Tunnel Enrollment Read-only Bridge

- Adds capability `tunnel_enrollment_read_only` to the existing External Access agent heartbeat.
- Reads only `/share/smart-pro/tunnel/enrollment.json` produced by Smart Pro Tunnel 0.1.4 and validates contract, 32-byte WireGuard public key, source, restrictive file permissions and fail-closed safety flags.
- Forwards only the public WireGuard key, Tunnel version, source and bounded timestamp through the already authenticated Installation heartbeat.
- Never reads or forwards the Tunnel private key, Portal secrets, Gateway credentials or Home Assistant credentials.
- Adds no Secure Command Channel executable capability and no Tunnel/Gateway/DNS/Caddy/public-ingress mutation authority.
- Existing Gateway observation, pairing, service access, Managed Backup and Generation-1 Control Plane authority remain unchanged.

# 2.4.42 — Managed External URL Read-only Gateway Observation Foundation

- Extends the existing `smart-pro-external-access-agent-v1` heartbeat with a separate `smart-pro-external-access-gateway-observation-v1` read-only observation block.
- Accepts only bounded Gateway Registry metadata returned through the already authenticated Installation heartbeat: exact Installation binding, registry digest, lifecycle state, opaque hostname, peer `/32`, source and timestamps.
- Keeps accepted Gateway observations in memory only and reports freshness on later heartbeats; no Gateway authority is persisted locally.
- Rejects mismatched Installation IDs, invalid hostnames/peer addresses, unknown lifecycle states, missing read-only markers or any runtime authority.
- Adds no Secure Command Channel capability and leaves the frozen Generation-1 authority digest unchanged.
- Adds no Supervisor privilege, Tunnel discovery permission, WireGuard key access, DNS/Caddy/registry write, router mutation, inbound listener or public-ingress authority.
- Smart Pro Tunnel 0.1.3 remains byte-identical.

# 2.4.41 — Managed External URL Agent Identity Foundation

- Adds a dedicated persistent External Access node identity and HMAC-derived proof over the existing authenticated Portal heartbeat.
- Reports bounded local Home Assistant target readiness only; no local URL/token is exposed.
- Tunnel runtime, gateway connection, DNS/public route, inbound listener, UPnP and router mutation remain OFF.
- Fails closed if Portal advertises External URL runtime authority before a later milestone.
- Preserves Managed Backup 2.4.40 storage-handoff readiness unchanged.

# 2.4.40 — Managed Backup Storage Handoff & Export Readiness Foundation

- Adds `storage_handoff_readiness` to the separate Managed Backup agent contract.
- Re-verifies the exact already-created local Managed Backup against the local Home Assistant backup inventory and exposes only job ID, digest, backup type and bounded source state.
- Raw Home Assistant backup slug remains local in `/data/managed_backup_agent.json` (0600).
- Accepts only the provider-neutral Portal target contract `provider_unconfigured`; no upload grant, provider ID, URL or credential is accepted.
- No backup bytes are opened or transmitted; upload/storage/replication/retention/restore/delete remain OFF.
- Frozen Generation-1 Control Plane authority remains unchanged.

# 2.4.39 — Managed Backup Controlled Local Backup Creation

- Adds `local_backup_create` to the separate Managed Backup agent contract.
- Accepts only a short-lived HMAC-signed local-only job envelope bound to Installation ID, Node ID, policy hash and nonce.
- Creates exactly one Home Assistant full backup after local readiness is READY and verifies the returned backup slug against the local Supervisor backup inventory.
- Stores the raw slug only in local `/data/managed_backup_agent.json` (0600); heartbeat exposes only a SHA-256 digest and bounded result state.
- Exact replay is idempotent; a second/different job is rejected in this first-job-only milestone.
- Upload, storage, replication, retention, restore point, restore/delete/download and provider credentials remain unavailable.
- Frozen Generation-1 Control Plane authority remains 13 capabilities / unchanged digest.

## 2.4.38

- Προσθέτει read-only `smart-pro-managed-backup-local-readiness-v1` πάνω στο ήδη verified Managed Backup agent heartbeat.
- Δηλώνει capability `local_backup_readiness` χωρίς να προσθέτει νέα remote command authority.
- Επαληθεύει μόνο ότι υπάρχουν node identity, Secure Command Channel readiness, SYNC policy/schedule, local Home Assistant Token και διαθέσιμο το υπάρχον read-only backup inventory endpoint.
- Δεν μεταφέρει Home Assistant Token, backup slug/name/path/size/password/content, provider credentials ή raw backup data.
- Δεν δημιουργεί Managed Backup, δεν καλεί νέο backup/restore mutation, δεν ανεβάζει αρχείο και δεν συνδέεται με storage.
- Το `data_plane_authorized` παραμένει ρητά false και οποιαδήποτε μη αναμενόμενη Portal authority παραμένει fail-closed.
- Η frozen Generation-1 Control Plane allow-list/digest παραμένει αμετάβλητη.

## 2.4.37

- Προσθέτει το πρώτο Managed Backup Agent Identity Foundation πάνω στο υπάρχον authenticated Installation heartbeat, χωρίς νέο inbound port ή public endpoint.
- Δημιουργεί μία επίμονη τυχαία 64-hex Node identity στο `/data/managed_backup_agent.json` με mode 0600 και τη διατηρεί σε update/restart.
- Παράγει 16-hex node-key proof από το ήδη provisioned per-installation Secure Command Channel secret και το canonical Installation ID, χωρίς να εκθέτει το secret στο Portal, UI ή logs.
- Στέλνει το contract `smart-pro-managed-backup-agent-v1` με capabilities `node_identity` και `policy_receive`, ώστε το Portal 3.6.235+ να μπορεί να κάνει fail-closed idempotent binding του node.
- Λαμβάνει και αποθηκεύει μόνο τη verified Managed Backup policy (daily, retention, timezone, local window, deterministic slot, policy hash) από το authenticated heartbeat.
- Οποιαδήποτε data-plane authority που τυχόν εμφανιστεί απορρίπτεται λειτουργικά: backup creation, Home Assistant backup I/O, upload/storage, replication, retention, restore, delete και provider credentials παραμένουν OFF.
- Δεν αλλάζει τη frozen Generation-1 Control Plane allow-list/digest, Guardian, Smart Updates, Vacation Mode, service-access enforcement, diagnostics, pairing ή Managed Support.

## 2.4.36

- Διορθώνει τη συνέπεια UI όταν η συνδρομή απενεργοποιεί υπηρεσίες: το Technician Center δείχνει τον Φρουρό και τα Smart Updates ως read-only/κλειδωμένα χωρίς να διαγράφει τις αποθηκευμένες ρυθμίσεις.
- Διορθώνει το κεντρικό status banner ώστε να μη γράφει «παρακολουθείται ενεργά» όταν το Guardian entitlement είναι OFF.
- Επαναφέρει στο τέλος κάθε health render το authoritative support-request gate ώστε η οθόνη να μην ξαναενεργοποιεί οπτικά το κουμπί υποστήριξης.
- Το δοκιμαστικό Guardian email απορρίπτεται server-side όταν το Guardian entitlement είναι OFF.
- Runtime enforcement, pairing, Managed relationship και Generation-1 Control Plane authority παραμένουν αμετάβλητα.

## 2.4.35

- Ενεργοποιεί το `smart-pro-service-access-v1` από το Smart Pro Portal ως authoritative service gate για τις συνδρομητικές λειτουργίες.
- Guardian runtime και Safe Guardian Test απαιτούν πλέον ενεργό `guardian_monitoring` entitlement και έγκυρη Portal verification.
- Smart Updates runtime και Safe Smart Updates Test απαιτούν πλέον ενεργό `update_guidance`; γίνεται επιπλέον re-check πριν από πραγματικό backup/update mutation.
- Home Assistant Backup/Health diagnostics σταματούν τη συλλογή όταν το `backup_health` entitlement δεν είναι ενεργό.
- Το local κουμπί κανονικού αιτήματος υποστήριξης κλειδώνει όταν το `support_requests` entitlement είναι OFF και το backend endpoint απορρίπτει fail-closed.
- Generic platform-gated runtime (π.χ. Vacation Mode) ακολουθεί πλέον `platform_services_active`.
- Trial / Active / Grace μπορούν να κρατούν υπηρεσίες ενεργές σύμφωνα με τα Portal entitlements. Expired / Suspended / Trial-expired τις κλείνουν.
- Η persistent Managed σχέση παραμένει ανεξάρτητη από την πληρωμένη συνδρομή και δεν αλλάζει.
- Προστίθεται συμβατότητα plan `complete` στο local subscription normalizer.
- Δεν αλλάζει το Generation-1 Control Plane executable authority: οι 13 signed capabilities παραμένουν ίδιες.

## 2.4.34

- Κλειδώνει το Generation-1 Control Plane authority ως frozen baseline χωρίς καμία νέα executable capability.
- Προσθέτει read-only freeze metadata: `smart-pro-control-plane-freeze-v1`, freeze ID `generation-1-20260927` και SHA-256 authority digest.
- Το digest καλύπτει το ακριβές executor allow-list, τις 11 command families, τα 11 local-only boundaries και το βασικό security envelope (command contract, TTL, clock skew και replay/binding guards).
- Διατηρεί απαράλλακτες και τις 13 signed capabilities της 2.4.33. Δεν προσθέτει Home Assistant action, secret transport, destructive/recovery action ή νέα remote authority.

## 2.4.33

- Προσθέτει το read-only contract `smart-pro-control-plane-capabilities-v1` μέσα στο υπάρχον authenticated Technician Center heartbeat.
- Δηλώνει ρητά τις 11 Generation-1 command families, τις 13 ακριβείς signed capabilities και τα deliberate local-only boundaries χωρίς να εκθέτει secrets ή raw entity IDs.
- Η ίδια `CONTROL_PLANE_ALLOWED_CAPABILITIES` allow-list χρησιμοποιείται πλέον τόσο από τον command executor όσο και από το manifest, ώστε η δήλωση authority να μην μπορεί να αποκλίνει από το πραγματικό Tools enforcement.
- Το Generation-1 scope δηλώνεται `scope_complete=true`: Guardian, Smart Updates και Vacation Mode αποτελούν το remote-managed configuration/action scope· SMTP credentials, Safe Test device name, raw Vacation selections, Managed Support manual pause, pairing/recovery identity, HA token, MeshCentral secrets και privileged recovery παραμένουν local-only.
- Δεν προστίθεται νέα command capability, Home Assistant service call, secret transport ή privileged recovery λειτουργία.

# 2.4.32 — Vacation Mode Controlled Policy

- Adds `vacation_policy_manage` and `vacation_master_manage` to the existing signed command channel.
- Vacation entity selections remain local-only.
- Remote ON is runtime-guarded when selected devices exist.
- Schedule mutation is blocked while a live Vacation runtime is active.

# 2.4.31 — Guardian Master + Safe Test Policy
- Adds guarded `guardian_master_manage` on the verified Secure Command Channel.
- Remote Guardian OFF is fail-closed while a real offline Guardian incident or active Safe Guardian Test exists.
- Remote Guardian ON requires at least one monitored category.
- Adds `guardian_safe_test_policy_manage` for delay, clear timing and test-email boolean only.
- Safe Test policy cannot change while a test is active; email=true requires an already stored local SMTP credential.
- SMTP password, Safe Test device name, Vacation Mode and privileged recovery settings remain local/outside remote-write scope.
- Preserves all 2.4.30 Guardian/Smart Updates behavior and command-channel protections.

# 2.4.30 — Smart Updates Master + Safe Test
- Adds bounded Secure Command Channel control for Smart Updates master.
- Remote enable is fail-closed unless Notify-only is already ON.
- Adds Safe Smart Updates Test action using existing simulation-only engine.
- Exposes bounded, non-secret Safe Test result telemetry to the Portal.
- Preserves all 2.4.29 Guardian/Smart Updates policy behavior.

# 2.4.29 — Smart Updates Controlled Policy

- Adds `smart_updates_policy_manage` on the verified Secure Command Channel.
- Allows only targets, maturity wait, backup wait, evaluation delay, rollback offline threshold and notify-only to change remotely.
- Keeps `auto_update_enabled` outside remote-write scope.
- Uses exact expected-state conflict protection, strict Tools-side bounds, atomic local save and read-back verification before `smart_updates_policy_applied`.
- Requires at least one update target for Portal-originated writes.
- Adds server-side normalization bounds for Smart Updates policy values while preserving existing local settings and engine behavior.
- Keeps Safe Smart Updates Test, master enable/disable, Vacation Mode and privileged controls for later milestones.

# 2.4.28 — Guardian Controlled Actions

- Adds the first signed non-settings Guardian action capabilities on the verified Secure Command Channel.
- `guardian_safe_test_start` starts the existing Safe Guardian Test using only the locally stored test policy; Portal cannot provide arbitrary delay/device/email parameters.
- `guardian_safe_test_cancel` safely clears an active virtual Guardian test without touching real Home Assistant entities.
- `guardian_email_test` sends one technical alert test email using the locally stored SMTP credential; no credential is returned to Portal.
- Adds bounded Safe Guardian Test runtime telemetry to the Technician Center heartbeat: status, request code, countdowns and a short status message.
- Keeps Guardian enable/disable, Safe Test policy, SMTP credentials, Smart Updates, Vacation Mode, pairing and privileged settings outside remote action scope.
- Preserves all Secure Command Channel HMAC, TTL, nonce/replay, installation-binding and acknowledgement protections.

# 2.4.27 — Controlled Guardian Monitoring Scope

- Adds the second low-risk Secure Command Channel capability: `guardian_scope_manage`.
- Allows remote control only of the eight Guardian categories already visible in the local Technician Center: lights, switches, binary sensors, climate, covers, cameras, locks and water heaters.
- Requires at least one monitored category for Portal-originated changes.
- Uses expected-state conflict protection, strict allow-list validation, atomic local save and read-back verification before acknowledgement.
- Preserves the hidden generic `sensor` domain unchanged; it remains outside remote-write scope.
- Keeps Guardian enable/disable, Safe Test, SMTP, Smart Updates, Vacation Mode, pairing and privileged settings outside remote-write scope.

# 2.4.26 — Controlled Guardian Settings Management

- Extends the verified `smart-pro-command-channel-v1` with the first real settings capability: `guardian_settings_manage`.
- Accepts only three low-risk Guardian policy values: check interval, alert grace and battery threshold.
- Enforces strict Tools-side bounds and an exact expected-state check before writing.
- Rejects stale Portal previews with `guardian_state_conflict` instead of overwriting newer local changes.
- Persists through the existing atomic `/data/tech_settings.json` path and performs local read-back verification before acknowledgement.
- Keeps Guardian enable/disable, monitored domains, Safe Test, SMTP, Smart Updates, Vacation Mode, pairing and privileged settings outside the remote-write scope.
- Preserves the no-op secure-channel probe and all Milestone 2 replay/TTL/HMAC protections.

# 2.4.25 — Secure Command Channel Foundation

- Adds `smart-pro-command-channel-v1` transported only on the authenticated Portal heartbeat.
- Accepts per-installation provisioned HMAC key material and stores it only under `/data` with mode 0600.
- Verifies installation identity, key ID, HMAC signature, TTL, nonce and replay state before any command execution.
- Adds bounded replay cache and persistent acknowledgement state.
- Foundation allows only a no-op `control_plane_probe`; no settings mutation is implemented.
- Keeps Technician Center v1 read-only telemetry unchanged.

## 2.4.24 — Technician Center Portal Read-only Contract
- Adds `smart-pro-technician-center-v1` to the existing authenticated Portal heartbeat.
- Mirrors selected General / Guardian / Automations settings read-only.
- Excludes secrets and raw Home Assistant entity selections.
- Adds no Portal command or write path.

# 2.4.23 — Guardian Core Reliability & Operations Contract

- Promotes Guardian heartbeat telemetry to backward-compatible `smart-pro-guardian-v2` while preserving the existing `enabled/status/last_check_at/offline_count/low_battery_count` fields.
- Adds reason codes, last successful check, grace-vs-alerted counts, retry state, last alert/request reference, recovery metadata, monitoring-scope count and email-configuration state for the future Portal Guardian Operations Center.
- Persists real Guardian offline/low-battery runtime state under `/data` so add-on restarts do not restart the incident grace period or create duplicate automatic alerts.
- Changes automatic offline delivery to acknowledgement-first semantics: a Portal failure leaves the incident queued and retries instead of marking it delivered.
- Keeps email as an independent Guardian alert channel. Real Guardian alerts always attempt `alert@smart-pro-system.gr`; SMTP failures are retried, email delivery telemetry is exposed in the Guardian v2 contract, and successful Portal requests include their request code in the email.
- Adds explicit recovery telemetry when previously offline entities return. Automatic request closure remains outside this milestone and is reserved for later Incident Engine integration.
- Adds backend bounds for Guardian frequency, alert delay, battery threshold and safe-test timings.
- Separates Smart Vacation execution from the Guardian enable/disable gate so disabling Guardian no longer disables Vacation Mode.
- Stops returning the stored SMTP password to the browser. A blank password field now preserves the existing secret, and privileged settings writes require an active technician session.
- Replaces the static `Internet: Online` label with the truthful `Internet: χωρίς ξεχωριστό probe` until a real network probe is intentionally designed.
- Keeps low-battery behavior as an explicit `HA notification only` policy; it contributes to Guardian attention but does not create an automatic Portal ticket.
- Automatic offline request/email device references are bounded opaque domain+hash references; raw Home Assistant entity IDs remain local.
- Does not change Home Assistant diagnostics, Remote Access, Managed Support, subscription policy or the future Guardian+Diagnostics+Incident Engine project.

# 2.4.22 — Home Assistant Backup Health Diagnostics

- Adds read-only Backup Health collection through the existing Home Assistant `supervisor/api` WebSocket proxy and `/backups/info`.
- Reports only aggregate counts, staleness threshold and the newest completed backup containing Home Assistant configuration.
- Backup names, slugs, locations, sizes, passwords and raw backup metadata are discarded locally.
- Promotes the diagnostics contract to `smart-pro-home-assistant-diagnostics-v7`.
- Backup creation, deletion, download and restore remain outside this diagnostics milestone and stay reserved for the later Smart Pro Tools backup/restore project.

# 2.4.21 — Fresh Diagnostic Check Handshake

- Adds a bounded Portal→Tools request over the existing heartbeat response.
- Forces one read-only aggregate Home Assistant diagnostics refresh when requested.
- Sends matching acknowledgement and fresh snapshot on a second authenticated heartbeat.
- No Home Assistant mutation, remote access grant, or raw identifier expansion.

# 2.4.20 — Home Assistant Supervisor + Add-on Diagnostics Foundation

- Adds read-only aggregate Supervisor/app diagnostics through the official Home Assistant `supervisor/api` WebSocket proxy using the existing admin HA token.
- Reads only `/supervisor/info` and `/addons`; Smart Pro Tools does **not** enable `hassio_api` and does not use `SUPERVISOR_TOKEN`.
- Exports only strict-whitelist aggregates: Supervisor healthy/supported/update state/version and app totals for running/stopped/error/unknown/update-available/unavailable/system-managed.
- App names, slugs, repositories, URLs, options and per-app versions are discarded locally and never sent to Portal.
- Observation-only diagnostics; no start/stop/restart/update action, no Supervisor mutation, no Incident Engine root behavior.
- Diagnostic contract promoted to `smart-pro-home-assistant-diagnostics-v6`.

# 2.4.19 — Home Assistant Integration Diagnostics Foundation

- Προσθέτει read-only aggregate diagnostics για Home Assistant config entries μέσω του επίσημου WebSocket command `config_entries/get`.
- Μετρά συνολικά config entries, distinct integration domains, loaded/disabled entries και bounded attention counters για setup error, retry, migration error και failed unload.
- Δεν εξάγει config-entry IDs, titles, unique IDs, user-defined names ή raw config-entry payloads.
- Intentionally disabled integrations παραμένουν inventory context και δεν θεωρούνται από μόνες τους attention.
- Δεν προστίθεται Supervisor privilege, `hassio_api`, mutation action ή αλλαγή σε Guardian/Smart Updates.
- Diagnostic contract προάγεται σε `smart-pro-home-assistant-diagnostics-v5`.

# 2.4.18 — Home Assistant System Log Redaction Hardening

- Hardens the selected Home Assistant system-log sanitizer after live QA exposed installation-specific labels/identifiers in otherwise sanitized summaries.
- Redacts additional entity domains (including `timer.*`), device IDs/hints, user-created automation/script aliases, ESPHome node labels, Home Assistant add-on slugs/routes and local add-on hostnames.
- Keeps logger/component names and technical error meaning where safe, while preventing raw device/entity/alias identifiers from leaving the installation.
- Does not change Home Assistant permissions, collection source (`system_log/list`), Guardian, Smart Updates, Device Diagnostics, lifecycle policies or Incident Engine behavior.

# 2.4.17 — Home Assistant WebSocket Reader Hotfix

- Restores the missing `_ha_ws_read_exact()` helper accidentally omitted from 2.4.16.
- Fixes `system log websocket_failed` while preserving the same read-only `system_log/list` diagnostics design.
- Does not change Home Assistant permissions, Guardian, Smart Updates, device diagnostics, Portal heartbeat schema or lifecycle behavior.
- Keeps `/api/error_log` only as compatibility fallback and preserves local redaction/bounds.

# 2.4.16 — Home Assistant System Log WebSocket Compatibility

- Replaces `/api/error_log` as the primary selected-log source with the official admin-only `system_log/list` WebSocket command.
- Fixes HAOS/Supervised installations where `/api/error_log` returns 404 because Supervisor disables duplicate Core log-file output.
- Keeps `/api/error_log` only as a compatibility fallback for Core/container installations.
- Adds no Supervisor API permission and does not change Guardian, Smart Updates, pairing, Managed Support or Portal policy behavior.
- Continues bounded local redaction before any selected log summary leaves the installation.

## 2.4.15 — Home Assistant Selected Error Log Foundation

- Προσθέτει read-only συλλογή του επίσημου Home Assistant `/api/error_log` με το ήδη υπάρχον HA token· δεν απαιτεί Supervisor/manager permission.
- Η ανάγνωση είναι bounded σε 64 KiB και έως 24 επιλεγμένες γραμμές.
- Πριν φύγει οτιδήποτε από την εγκατάσταση γίνεται aggressive redaction για credentials, URLs, IP/MAC, email, UUID, entity IDs, local paths και opaque identifiers.
- Το heartbeat μεταφέρει μόνο sanitized excerpt + counts/status/fingerprint. Δεν μεταφέρει raw Home Assistant log.
- Η συλλογή παραμένει ανεξάρτητη από Guardian / Smart Updates.

## 2.4.14 — Home Assistant Device Diagnostics Foundation

- Προσθέτει read-only aggregate Device Registry / Entity Registry diagnostics μέσω των επίσημων Home Assistant WebSocket registries.
- Συσχετίζει entity health με devices μόνο τοπικά/in-memory και στέλνει στο Portal αποκλειστικά counters.
- Νέα aggregates: registered devices/entities, disabled devices/entities, devices με unavailable/unknown/low-battery entities και attention entities χωρίς device mapping.
- Δεν εξάγονται device IDs, entity IDs, names, areas, config-entry IDs ή raw registry payloads.
- Ανεξάρτητο από Guardian και Smart Updates. Raw device logs παραμένουν εκτός milestone.

## 2.4.13 — Home Assistant Maintenance Semantics

- Upgrades the Home Assistant diagnostics contract to `smart-pro-home-assistant-diagnostics-v2`.
- Separates actionable update entities from skipped update entities.
- Adds read-only aggregate Home Assistant Repairs collection through `repairs/list_issues`.
- Sends only aggregate repair counts/severity/fixable counts; never issue IDs, domains, descriptions, URLs or translation payloads.
- Keeps maintenance information separate from runtime/entity health classification.
- Adds a tiny stdlib-only read-only WebSocket client so no new Python dependency is required.

# Changelog

## 2.4.12

- Προσθέτει το πρώτο ανεξάρτητο Home Assistant Diagnostics Foundation χωρίς να αλλάζει τη λογική Guardian, Smart Updates, Managed Support ή αιτημάτων.
- Συλλέγει ανά έως 60 δευτερόλεπτα strict-whitelist runtime/entity-health σύνοψη από `/api/config` και `/api/states` και τη στέλνει μόνο μέσα στο ήδη ασφαλές Portal heartbeat.
- Η σύνοψη περιλαμβάνει μόνο HA version/core state/safe mode και αθροιστικούς μετρητές entities: total, unavailable, unknown, low-battery και pending updates. Δεν αποστέλλονται entity IDs, friendly names, device IDs, areas, τοποθεσία, URLs, HA token ή raw logs.
- Ο collector είναι ανεξάρτητος από το αν ο Guardian είναι ενεργός και χρησιμοποιεί δικό του contract `smart-pro-home-assistant-diagnostics-v1`.
- Δεν προστίθεται Supervisor privilege, `hassio_api`, νέο network privilege ή raw Home Assistant log access.
- Προσθέτει `DIAGNOSTICS.md` ώστε μελλοντικά updates να κάνουν ρητό diagnostic-impact check αντί να βασίζονται στη μνήμη του operator/developer.

## 2.4.11

- Διορθώνει οριστικά το stale Ingress/browser UI μετά από update: τα static UI responses (`index.html`, JavaScript/CSS και λοιπά μη-API assets) αποστέλλονται πλέον με `no-store/no-cache`, ώστε παλιό `index.html` να μην μπορεί να κρατήσει παλιό cache key του `script.js`.
- Ανανεώνει και το explicit `script.js` cache key σε `v=2411`.
- Δεν αλλάζει τη λογική manual/automatic requests του 2.4.9, τον Guardian, το heartbeat payload, Managed Support, Managed Network, Router Compatibility ή permissions.
- Με μόνο ενεργό automatic Guardian alert, το UI πρέπει να εμφανίζει ξανά ενεργό «Αίτημα Υποστήριξης» και να κρατά το automatic alert μόνο στο ιστορικό/incident context.

## 2.4.10

- Διορθώνει cache-busting του `script.js` μετά το 2.4.9, ώστε το Home Assistant Ingress/browser να φορτώνει τη νέα λογική διαχωρισμού χειροκίνητων αιτημάτων και αυτόματων Guardian alerts αντί για cached JavaScript της 2.4.8.
- Δεν αλλάζει το request data model, τα Portal APIs, τον Guardian, το heartbeat, Managed Support, Managed Network, Router Compatibility ή permissions.
- Με ενεργό μόνο αυτόματο Guardian alert, το κουμπί «Αίτημα Υποστήριξης» πρέπει να παραμένει διαθέσιμο για νέο χειροκίνητο αίτημα πελάτη.

## 2.4.9

- Διαχωρίζει τα ενεργά αιτήματα πελάτη από τις αυτόματες ειδοποιήσεις του Φρουρού χωρίς αλλαγή του υπάρχοντος request history.
- Το κουμπί «Αίτημα Υποστήριξης» μπλοκάρεται πλέον μόνο από ενεργό χειροκίνητο αίτημα πελάτη, όχι από αυτόματο Guardian alert.
- Όταν ο Φρουρός διαχειρίζεται offline συσκευή, το UI δεν κλειδώνει πλέον το χειροκίνητο αίτημα· ο πελάτης μπορεί να ανοίξει παράλληλο ξεχωριστό case.
- Διατηρεί backward-compatible fallback όταν το Portal δεν έχει ακόμη αναβαθμιστεί και συνεχίζει να εκθέτει μόνο το παλιό συνολικό `open_request_count`.
- Αποθηκεύει το νέο `manual_open_request_count` και το `automatic_alert_count` από το Portal, διατηρώντας και το συνολικό count για συμβατότητα.
- Προσθέτει στο υπάρχον heartbeat ελάχιστο read-only Guardian summary: ενεργό/ανενεργό, health state, τελευταία ολοκληρωμένη μέτρηση, πλήθος offline συσκευών και πλήθος χαμηλών μπαταριών.
- Δεν αποστέλλει ονόματα entities, HA token, Portal token, credentials ή άλλα μυστικά στο Guardian summary.
- Δεν αλλάζει Managed Policy, Managed Network, Router Compatibility, Smart Updates, Vacation Mode ή Remote Support permissions.

## 2.4.8

- Αποσυνδέθηκε η τοπική Managed connection policy από την κατάσταση πληρωμής/συνδρομής.
- `expired`, `suspended`, `pending_activation`, `services_active=false` και το subscription entitlement παραμένουν ορατά ως diagnostics/accounting context αλλά δεν σταματούν πλέον από μόνα τους το Managed agent.
- Το local policy εξακολουθεί να αποτυγχάνει fail-closed όταν λείπει Portal pairing ή Installation ID, όταν η Portal verification έχει λήξει ή όταν είναι ενεργό το `managed_remote_support_manual_pause`.
- Το `authorization.valid_until` βασίζεται πλέον μόνο στο Portal verification deadline και όχι στη λήξη ή grace deadline της συνδρομής.
- Προστέθηκαν τα μη μυστικά diagnostics `policy_basis=managed_relationship` και `subscription_gate_enforced=false`.
- Το Managed Policy contract παραμένει v1 για συμβατότητα με Smart Pro Managed Support 3.19.0. Δεν αλλάζουν Guardian, Smart Updates, requests, network contract ή άλλες λειτουργίες του Smart Pro Tools.

## 2.4.7

- Προστέθηκε απομονωμένο Managed Network Discovery Foundation χωρίς αλλαγή δικαιωμάτων και χωρίς Supervisor API.
- Το Smart Pro Tools, που ήδη εκτελείται με `host_network: true`, διαβάζει read-only το Linux `/proc/net/route` και επιλέγει μόνο ενεργό default gateway με RFC1918 IPv4 διεύθυνση.
- Παράγεται ατομικά το μη-μυστικό `/share/smart-pro-system/managed-network.json` για read-only κατανάλωση από το Smart Pro Managed Support.
- Το contract περιλαμβάνει Installation ID, κατάσταση/reason code, interface, private gateway candidate, metric και ανεξάρτητο 120s liveness lease.
- Δεν γίνεται HTTP/HTTPS probe, Router proxy, header rewrite ή απομακρυσμένη πρόσβαση σε αυτή την έκδοση.
- Δεν προστίθεται `hassio_api`, Supervisor token ή άλλο νέο privilege. Δεν αποθηκεύονται router credentials, Portal tokens, HA tokens ή αυθαίρετα URLs/IPs από browser.
- Αν λείπει Installation ID, δεν υπάρχει ιδιωτικό default gateway ή αποτύχει η ανάγνωση route, το network contract αποτυγχάνει fail-closed και δεν εκθέτει router candidate.
- Οι υπάρχουσες λειτουργίες Managed Policy, Guardian, Smart Updates, αιτήματα, pairing, heartbeat, UI και Portal synchronization παραμένουν αμετάβλητες.

## 2.4.6

- Προστέθηκε το entitlement `managed_remote_support` στο ελεγχόμενο allow-list του Portal subscription contract.
- Προστέθηκε απομονωμένη Managed Policy & Health Bridge Foundation χωρίς enforcement στις υπάρχουσες λειτουργίες Smart Pro Tools.
- Το Smart Pro Tools παράγει ατομικά το ανακατασκευάσιμο `/share/smart-pro-system/managed-policy.json` για το μελλοντικό Smart Pro Managed Support 3.x.
- Το policy περιλαμβάνει Installation ID, allowed/denied, reason code, subscription/verification state, authorization deadline και ανεξάρτητο 120s Tools-liveness lease.
- Active/Grace μπορούν να επιτρέψουν Managed Support μόνο με έγκυρη επαλήθευση, ενεργές υπηρεσίες, entitlement και χωρίς manual pause. Expired/Suspended/Pending/παλιά επαλήθευση αποτυγχάνουν fail-closed.
- Η 72ωρη Portal verification cache παραμένει, αλλά διαχωρίζεται από το τοπικό Tools-liveness lease ώστε διακοπή του Smart Pro Tools να μπορεί αργότερα να σταματά γρήγορα το Managed runtime.
- Προστέθηκε μικρή read-only ένδειξη Managed Support στην υπάρχουσα κάρτα συνδρομής για QA.
- Δεν αλλάζουν Guardian, Smart Updates, αιτήματα, MeshCentral banner, SMTP, pairing ή το υπάρχον `subscription_runtime_allowed()`.

## 2.4.5

- Διορθώθηκε λειτουργικό πρόβλημα κύλισης στην κύρια σελίδα του Smart Pro Tools μετά την προσθήκη της κάρτας συνδρομής.
- Η σελίδα μπορεί πλέον να επεκτείνεται κατακόρυφα και να κάνει scroll, ώστε να παραμένουν προσβάσιμα τα «Αιτήματα Υποστήριξης» και το «Ημερολόγιο Συντήρησης».
- Διατηρήθηκε ξεχωριστή εσωτερική κύλιση στις λίστες ιστορικού όταν αυξάνονται οι εγγραφές.
- Δεν άλλαξε η λογική συνδρομής, heartbeat, pairing, Guardian ή αιτημάτων της 2.4.4.

## 2.4.4

- Προστέθηκε ασφαλής συγχρονισμός της συνδρομής ανά εγκατάσταση από το Smart Pro Portal 2.6.1 μέσω pairing και heartbeat.
- Αποθηκεύεται μόνο το ελάχιστο συμβόλαιο συνδρομής: πακέτο, κατάσταση, ημερομηνίες, ημέρες, entitlements και πολιτικές· δεν λαμβάνονται στοιχεία πληρωμών.
- Η τελευταία έγκυρη κατάσταση διατηρείται για ανοχή επαλήθευσης 72 ωρών σε προσωρινή διακοπή Internet ή Portal.
- Προστέθηκε καθαρή προβολή πακέτου, κατάστασης, υπολοίπου, σχετικής ημερομηνίας και κατάστασης επαλήθευσης.
- Οι παλιές τοπικές ρυθμίσεις συνδρομής κρύβονται όταν υπάρχει ενεργό Portal pairing και παραμένουν μόνο ως fallback χωρίς Portal.
- Η έκδοση είναι σκόπιμα sync-and-display only: δεν εφαρμόζει ακόμη περιορισμούς σε Φρουρό, Smart Updates, αιτήματα ή πληροφορίες συστήματος.
- Το pairing, το Installation ID και η υπάρχουσα λειτουργία αιτημάτων παραμένουν ανεπηρέαστα.

## 2.4.3

- Συνδέθηκαν τα αιτήματα του Smart Pro Portal με την υπάρχουσα ενότητα «Αιτήματα Υποστήριξης» του Smart Pro Tools.
- Εμφανίζονται κωδικός αιτήματος, κατηγορία, ακριβής κατάσταση, περιγραφή και τελευταία ενημέρωση.
- Τα ενεργά αιτήματα εμφανίζονται πρώτα και η επάνω ένδειξη δείχνει τον ενεργό κωδικό και την κατάστασή του.
- Το κεντρικό Installation ID ενημερώνεται αποκλειστικά από το ενεργό Portal pairing.
- Το προεπιλεγμένο Portal URL άλλαξε στο production `https://smart-pro-system.gr`.
- Το Home Assistant Token έγινε κρυφό πεδίο στη Διαμόρφωση.
- Το Home Assistant Token παραμένει πλέον στην πλευρά του server και δεν ενσωματώνεται στο JavaScript του browser.
- Διατηρήθηκε η υπάρχουσα λογική ενεργής/ληγμένης συνδρομής και η εκκαθάριση ενεργού αιτήματος μετά την ολοκλήρωση.
- Καθαρίστηκε η δομή του πακέτου ώστε να μην περιέχει διπλό nested add-on directory.

## 2.4.2

- Δημιουργήθηκε κοινό επαγγελματικό πρότυπο Automation Card για σημερινούς και μελλοντικούς αυτοματισμούς.
- Ανασχεδιάστηκαν οι κάρτες Smart Updates & Rollback και Smart Vacation Mode χωρίς αλλαγή της λειτουργικής τους λογικής.
- Προστέθηκαν καθαρά toggle switches, δυναμικές καταστάσεις και compact σύνοψη ανά αυτοματισμό.
- Προστέθηκε προσαρμοσμένη επιβεβαίωση πριν από την ενεργοποίηση πραγματικών αυτόματων ενημερώσεων.
- Προστέθηκαν tooltips και ενσωματωμένοι οδηγοί τεχνικού για Updates και Vacation Mode.
- Η ασφαλής δοκιμή Smart Updates έγινε συμπτυσσόμενη και διατηρεί όλα τα δοκιμασμένα σενάρια.
- Ανανεώθηκε το cache-busting των UI αρχείων για καθαρή φόρτωση μετά το update.

## 2.4.1

- Προστέθηκε ασφαλής δοκιμή Smart Updates μέσα στον κλειδωμένο τεχνικό πίνακα.
- Προσομοιώνονται notify-only, επιτυχής ενημέρωση, αποτυχία backup, αποτυχία εγκατάστασης και οι δύο διαδρομές rollback.
- Η δοκιμή απαιτεί κλειστό τον κεντρικό διακόπτη και δεν καλεί πραγματικές υπηρεσίες backup, update ή restore.
- Εμφανίζεται αναλυτικό αποτέλεσμα ανά στάδιο χωρίς αλλαγή ρυθμίσεων.

## 2.4.0

- Ενοποιήθηκε η πηγή έκδοσης για Home Assistant και Smart Pro Portal.
- Διορθώθηκε η πραγματική λειτουργία notify-only.
- Προστέθηκαν ασφαλείς έλεγχοι αποτυχίας backup, update και rollback.
- Το rollback χρησιμοποιεί το συγκεκριμένο backup slug.
