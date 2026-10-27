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
