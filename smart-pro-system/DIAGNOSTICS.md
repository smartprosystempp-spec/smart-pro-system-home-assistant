# Smart Pro Tools — Diagnostics Contract

## Purpose

Το Smart Pro Tools είναι η τοπική πηγή αλήθειας για diagnostics που μπορούν να μετρηθούν μέσα στην εγκατάσταση. Κάθε μελλοντικό update πρέπει πρώτα να κάνει **Diagnostic Impact Check**: αν αλλάζει runtime behavior, failure mode, Home Assistant integration ή customer-visible health, εξετάζεται αν χρειάζεται νέο/ενημερωμένο diagnostic fact.

## Contract v7 — Home Assistant + Device + Integration + Supervisor/Add-on + Backup Health + Selected System Log diagnostics

Contract ID: `smart-pro-home-assistant-diagnostics-v7`

Η έκδοση 2.4.19 συλλέγει ανεξάρτητα από Guardian/Smart Updates:

- Home Assistant version
- Core state
- Safe mode boolean
- aggregate total entity count
- aggregate unavailable entity count
- aggregate unknown entity count
- aggregate low-battery entity count (diagnostic threshold 15%)
- aggregate actionable update count
- aggregate detected/skipped update counts
- aggregate active Repairs count
- aggregate Repairs severity counts (`warning` / `error` / `critical`) και fixable count
- bounded reason/status codes


### Integration diagnostics foundation

Η 2.4.19 διαβάζει read-only το επίσημο WebSocket command `config_entries/get` και εξάγει μόνο aggregate counters: συνολικά config entries, distinct integration domains, loaded/disabled entries και attention counters για `setup_error`, `setup_retry`, `migration_error` και `failed_unload`. Τα config-entry IDs, titles, unique IDs και user-defined names χρησιμοποιούνται μόνο μέσα στο Home Assistant response και δεν αποστέλλονται στο Portal.

Intentionally disabled config entries δεν θεωρούνται αυτόματα health warning. Integration diagnostics είναι observation-only και δεν αποτελούν Incident Engine root σε αυτό το milestone.


### Supervisor / add-on diagnostics foundation

Η 2.4.50 μεταφέρει τα ίδια αυστηρά read-only Supervisor/Add-on aggregates στο υποστηριζόμενο direct Supervisor API (`http://supervisor/`) επειδή το Home Assistant 2026 μπλοκάρει πλέον add-on-originated `supervisor/api` μηνύματα στο Core WebSocket proxy. Το Smart Pro Tools ενεργοποιεί `hassio_api: true`, χρησιμοποιεί μόνο το container-scoped `SUPERVISOR_TOKEN` και `hassio_role: manager`, που είναι το ελάχιστο role που επιτρέπει `/addons` inventory και τις bounded Tunnel options/start/restart ενέργειες του Managed External URL runtime bridge. Το token δεν εκτίθεται σε Portal/UI/logs.

Προς το Portal επιτρέπονται μόνο aggregate/strict-whitelist facts: Supervisor version, healthy/supported/update booleans και counters για installed apps/add-ons (running, stopped, error, unknown, update available, unavailable, system managed). Ονόματα, slugs, repositories, URLs, options και per-app versions απορρίπτονται τοπικά.

Το milestone είναι observation-only. Δεν επιτρέπονται start/stop/restart/update actions και τα events δεν αποτελούν Incident Engine roots.

### Backup Health diagnostics foundation

Η 2.4.22 διαβάζει read-only το `/backups/info` μέσω του ίδιου επίσημου `supervisor/api` WebSocket proxy. Προς το Portal στέλνονται μόνο aggregate facts: συνολικά completed backups, πόσα περιέχουν Home Assistant, full/partial/protected counters, `days_until_stale`, χρόνος του νεότερου Home-Assistant backup, ηλικία, τύπος/protected flag και stale boolean.

Δεν αποστέλλονται backup names, slugs, locations, sizes, passwords ή raw backup metadata. Η λειτουργία **δεν** δημιουργεί, διαγράφει, κατεβάζει ή επαναφέρει backup. Η μελλοντική διαχείριση backup/restore από Smart Pro Tools θα παραμείνει action layer πάνω από το ίδιο normalized Backup Health contract, ώστε το Diagnostics/Portal να μη χρειαστεί επανασχεδιασμό.

Το `/backups/info` εκθέτει completed-backup inventory και stale threshold, όχι αξιόπιστο ιστορικό αποτυχημένων backup jobs. Failure history δεν εφευρίσκεται σε αυτό το milestone και θα προστεθεί μόνο όταν το μελλοντικό Smart Pro Tools backup automation έχει δικό του audited result contract.

### Selected Home Assistant error log

Η 2.4.17 διαβάζει read-only το επίσημο WebSocket command `system_log/list` με το ήδη ρυθμισμένο Home Assistant token. Δεν ενεργοποιεί `hassio_api`, δεν ζητά Supervisor manager role και δεν ανοίγει νέο privileged channel.

Η ανάγνωση περιορίζεται σε 64 KiB και έως 24 τελευταίες μη κενές γραμμές. Πριν από heartbeat εφαρμόζεται redaction για authorization/token/password/secret/API key, URL, IPv4/IPv6, MAC, email, UUID, entity IDs, device IDs/hints, user-created aliases, ESPHome node labels, Home Assistant add-on slugs/hostnames/routes, `/config`/`/ssl`/`/share` paths και μεγάλα opaque identifiers. Το Portal λαμβάνει μόνο το sanitized excerpt, counters, status και fingerprint. Raw log bytes δεν αποθηκεύονται ούτε εξάγονται.

### Device diagnostics foundation

Η 2.4.14 διαβάζει read-only τα Home Assistant Device Registry και Entity Registry και χρησιμοποιεί τα registry IDs **μόνο τοπικά/in-memory** για συσχέτιση. Προς το Portal επιτρέπονται μόνο aggregate counters: συνολικές/disabled συσκευές και entities, πλήθος συσκευών με unavailable/unknown/low-battery entities και πλήθος attention entities χωρίς device mapping.

Δεν επιτρέπεται να σταλούν raw device/entity/area/config-entry IDs, names ή registry payloads.

### Maintenance semantics

Τα updates/Repairs είναι **maintenance attention** και δεν μετατρέπονται από μόνα τους σε runtime fault ή Incident Engine root. Τα Repairs συλλέγονται μόνο ως aggregate counters. Δεν εξάγονται issue IDs, domains, descriptions, URLs ή translation payloads.

## Never send

Δεν επιτρέπεται να σταλούν μέσω του diagnostics heartbeat:

- Home Assistant token ή Authorization header
- entity IDs ή friendly names
- device IDs, registry IDs, area IDs/names
- latitude/longitude, location name, internal/external URLs
- raw `/api/config` payload
- raw Home Assistant logs
- credentials, secrets, passwords, API keys, session/grant identifiers

## Independence

Ο Home Assistant diagnostics collector πρέπει να συνεχίζει να λειτουργεί ανεξάρτητα από το Guardian enable/disable state. Ο Guardian μπορεί να εξελιχθεί αργότερα χωρίς να αποτελεί prerequisite για Home Assistant health telemetry.

## Future extensions

Per-add-on selected log collection και on-demand Supervisor/add-on probes/actions παραμένουν ξεχωριστά milestones. Το selected Home Assistant error-log excerpt της 2.4.17 δεν θεωρείται raw log export. Κάθε επέκταση απαιτεί allow-list, redaction, bounds και QA πριν προστεθεί στο contract.

## QA invariants

- Diagnostics collection must be read-only.
- Δεν αλλάζει Home Assistant state/service.
- Δεν δημιουργεί support request.
- Δεν αλλάζει Guardian/Smart Updates behavior.
- Portal export/log generation παραμένει read-only.
- Αλλαγές diagnostic contract τεκμηριώνονται εδώ και στο changelog.


## Home Assistant system-log source — 2.4.17

Hotfix note: η 2.4.17 επαναφέρει τον bounded WebSocket exact-reader helper που παραλείφθηκε κατά λάθος στην 2.4.16. Δεν αλλάζει contract ή permissions.

The primary selected-log source is the official admin-only Home Assistant WebSocket command `system_log/list`. This deliberately avoids Supervisor API permissions and works on HAOS/Supervised installs where the duplicate Core log file is disabled. The historical `/api/error_log` endpoint remains compatibility-only fallback. Raw exceptions, source paths, entity/device identifiers and credentials are never sent to Portal; only bounded, aggressively sanitized one-line summaries are emitted.


## Fresh Diagnostic Check v1 (2.4.21)

- Transport: existing authenticated Portal heartbeat only.
- Portal request contract: `smart-pro-fresh-diagnostic-check-v1`.
- Action: force one local read-only Home Assistant diagnostics collection.
- Ack: second heartbeat with exact request ID and fresh collection timestamps.
- No Home Assistant writes/service calls/restarts.
- No remote-access permission mutation.
- No raw entity/device identifiers are added to the heartbeat.
- Portal creates the new Diagnostic Run only after a matching, non-expired ack.
