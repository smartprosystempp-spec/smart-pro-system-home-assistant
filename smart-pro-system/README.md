Smart Pro System 3.0.24 — bounded read-only quarantine directory survey; no archive contents, SHA-256 recheck, Supervisor queries, delete or restore.
Smart Pro System 3.0.23: read-only recovery quarantine inventory. No hash recheck, live Supervisor query, cleanup or deletion authority.

## 3.0.21 — Admin-approved stale local-job reconciliation

Dedicated signed `reconcile_job` envelope from Portal 3.6.333. Exact historic job/node/nonce/policy and pre-restart started-at must match before local state is marked interrupted. This is not a backup creation command, has no cloud or Home Assistant backup I/O, and cannot bypass existing backup policies.

## 3.0.19 — Read-only local job guard evidence

- Shows persisted prior local-job state to diagnose PREVIOUS_JOB_INFLIGHT; no automatic reconciliation, cancellation, retry or backup creation.

## 3.0.18 — Managed Backup Exact Rejection Branch Evidence (diagnostic only)

- Report a bounded non-secret `reason_code` identifying the existing fail-closed branch when the exact local job is NOT ACCEPTED.
- Preserves all original validation branches, backup creation behavior, signatures, no retry, no queue reset, no extra data-plane authority.
- Supports authenticated Portal 3.6.331 reason presentation; no secret, path, HMAC, node ID, provider key or archive data rendered.

## 3.0.17 — Managed Backup Delivery Observation v1

A local-only receipt of the existing signed backup-job offer is reported via the authenticated heartbeat, without new authority or retries.

## 3.0.16 — Technician Supervisor Backup Staging v1

After independent Admin approval, an exact, HMAC-signed staging request may import the SHA-256 verified quarantine archive into the local Home Assistant Supervisor backup inventory. This is **not** a restore and does not overwrite current configuration. The technician must separately initiate restore through Home Assistant on an approved test installation.

## 3.0.15 — Recovery quarantine full GET + SHA-256 pilot

- Signed exact-object one-shot GET in an isolated Home Assistant add-on quarantine.
- Strict installation/node, HMAC, URL, object size/version and SHA-256 validation.
- No automatic Supervisor import/restore, no delete/replication.
- Only a technician, after separate approval in a future phase, may initiate restoration.

# Smart Pro System 3.0.14

## Managed Backup Controlled Presigned Primary Upload v1

Η 3.0.14 προσθέτει τον ελεγχόμενο executor για Portal-issued short-lived presigned primary upload. Τα OVH/S3 Access/Secret keys παραμένουν εκτός συσκευής. Το Smart Pro System δέχεται μόνο signed job για το ήδη verified local backup, ακριβές bucket/object, TTL έως 120s, Object Lock GOVERNANCE και full read-back SHA-256.

Safety: no provider credential delivery, no replication, no delete, no restore execution, no persistent storage authority. Legacy local-credential upload code παραμένει μόνο για backward compatibility και δεν χρησιμοποιείται όταν το handoff mode είναι `portal_presigned`.

Το Smart Pro System είναι ο τοπικός κόμβος της εγκατάστασης Home Assistant για σύνδεση με το Smart Pro Portal, κατάσταση υπηρεσιών, Guardian, Managed Backup, Managed External URL και ελεγχόμενη τεχνική υποστήριξη.

Η 3.0.13 προσθέτει μόνο το **Managed Backup presigned source-handoff foundation**: επαληθεύει ότι το local backup παραμένει διαθέσιμο για μελλοντική Portal-issued μεταφορά χωρίς να απαιτεί OVH/S3 credentials μέσα στη συσκευή. Δεν εκτελεί presigned URL ούτε S3 write.

Η 3.0.12 επαναφέρει την κανονική **automatic Smart Pro Tunnel replacement recovery** μετά το ολοκληρωμένο 3.0.11 diagnostic checkpoint. Αφαιρεί μόνο το προσωρινό Store diagnostic endpoint και το diagnostic scheduler pause, ενώ διατηρεί αυτούσια τα live-proven Store matching fixes των 3.0.9–3.0.10 και όλο το υπάρχον signed Control Plane / Portal behavior. Το εμφανιζόμενο όνομα είναι **Smart Pro System**, ενώ το εσωτερικό slug παραμένει `smart_pro_tools` για τεχνική συνέχεια.

## Τι βλέπει ο πελάτης
- κατάσταση σύνδεσης με Portal,
- τύπο χρήσης: μη συνδεδεμένο / standalone / συνδρομητής,
- πακέτο όταν υπάρχει,
- Managed Support entitlement και runtime ως διαφορετικές έννοιες,
- Smart Pro Tunnel runtime,
- Managed Backup κατάσταση,
- Managed External URL κατάσταση,
- Home Assistant / Guardian health.

Εμπορικές ενέργειες, πληρωμές και αλλαγές πακέτου παραμένουν στο Smart Pro Portal.
