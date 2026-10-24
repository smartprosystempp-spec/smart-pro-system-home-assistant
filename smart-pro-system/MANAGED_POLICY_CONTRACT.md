# Smart Pro Managed Policy Contract v1

## Σκοπός

Το Smart Pro Tools είναι η τοπική γέφυρα ταυτότητας και πολιτικής ανάμεσα στο Smart Pro Portal και στο `Smart Pro Managed Support` 3.x. Στην 2.4.8 το policy παραμένει ανεξάρτητο από Guardian/Updates/requests και χρησιμοποιείται από το Managed Support ως local fail-closed gate μαζί με τον ανεξάρτητο Broker authorization έλεγχο.

## Μεταφορά πολιτικής

Το contract γράφεται ατομικά στο:

`/share/smart-pro-system/managed-policy.json`

Το αρχείο είναι ανακατασκευάσιμο και δεν περιέχει μυστικά. Το μελλοντικό Managed add-on θα χαρτογραφεί το ίδιο Home Assistant `share` read-only.

## Διπλή προϋπόθεση ισχύος

Η Managed 3.x απαιτεί ταυτόχρονα:

1. `allowed == true` και τρέχων χρόνος <= `authorization.valid_until` όταν υπάρχει deadline.
2. τρέχων χρόνος <= `tools_liveness.lease_until`.

Η πρώτη προϋπόθεση καλύπτει Portal pairing, canonical Installation ID, πρόσφατη Portal verification και local manual pause. Η δεύτερη αποδεικνύει ότι το Smart Pro Tools εξακολουθεί να λειτουργεί τοπικά. Η κατάσταση πληρωμής/συνδρομής παραμένει diagnostics/accounting context και δεν αποτελεί πλέον local kill-switch του Managed connection.

## Portal verification vs Tools liveness

- Portal verification tolerance: έως 72 ώρες, όπως ήδη ορίζεται από το Subscription Core.
- Tools policy refresh: 30 δευτερόλεπτα.
- Tools liveness lease: 120 δευτερόλεπτα.

Άρα προσωρινή απώλεια Portal μπορεί να χρησιμοποιεί την τελευταία έγκυρη Portal verification εντός tolerance, αλλά διακοπή του ίδιου του Smart Pro Tools δεν αφήνει το Managed runtime ανεξέλεγκτο για 72 ώρες.

## Allow rules

Το local Managed connection policy επιτρέπεται μόνο όταν:

- υπάρχει ενεργό Portal pairing,
- υπάρχει canonical Installation ID,
- υπάρχει έγκυρο Portal snapshot,
- η επαλήθευση είναι ακόμη εντός tolerance,
- `manual_pause = false`.

Τα `status`, `services_active` και entitlement `managed_remote_support` διατηρούνται στο contract για diagnostics/accounting και UI, αλλά δεν κόβουν από μόνα τους τη συνεχή Managed σύνδεση. Το πραγματικό enrollment/de-enrollment παραμένει ανεξάρτητο server-side gate στον Broker μέσω της Managed node identity (`active` / `revoked`).

## Stable reason codes

Η 2.4.8 διατηρεί το contract v1 για συμβατότητα με Managed Support 3.19.0. Οι ενεργοί local reason codes είναι:

- `allowed_verified`
- `allowed_cached`
- `not_paired`
- `installation_id_missing`
- `subscription_unavailable`
- `verification_required`
- `manual_pause`
- `authorization_expired`

Τα παλαιότερα subscription-denial reason codes μπορεί να εμφανίζονται σε ιστορικά logs από 2.4.6–2.4.7, αλλά δεν χρησιμοποιούνται πλέον ως Managed connection kill-switch.

Οι reason codes είναι machine-facing και δεν πρέπει να αλλάζουν χωρίς αύξηση `policy_version`.

## Security boundary

Το local policy file **δεν είναι από μόνο του server authorization**. Το Smart Pro Managed Support πρέπει επιπλέον να επαληθεύεται από τον Smart Pro Remote Session Broker πριν διατηρήσει Managed runtime. Επομένως μια τοπική αλλοίωση του policy δεν αρκεί για να δημιουργήσει server-side πρόσβαση.

Δεν γράφονται στο contract:

- Portal installation token,
- Home Assistant token,
- MeshCentral credentials / `.msh`,
- κωδικοί pairing,
- email password,
- στοιχεία πληρωμών ή παραγγελιών.

## Health fields για μελλοντικό Admin Portal

Το contract θεμελιώνει τα πεδία που αργότερα μπορούν να συγκεντρώνονται στο Admin Portal:

- Smart Pro Tools version / online,
- Portal paired / sync health / last heartbeat,
- subscription status / verification state,
- Managed entitlement / allowed / reason,
- Tools liveness lease.

Το `bridge_state = policy_foundation` διατηρείται για συμβατότητα με το υπάρχον contract και δηλώνει ότι το Smart Pro Tools παράγει policy/health χωρίς να εκτελεί το ίδιο MeshAgent ή Broker permissions.
