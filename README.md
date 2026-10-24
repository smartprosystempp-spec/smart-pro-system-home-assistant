# Smart Pro System — Home Assistant

Επίσημο Home Assistant repository για την οικογένεια Smart Pro System.

## Περιεχόμενο της πρώτης vNext βάσης

- **Smart Pro System 3.0.0** — ο τοπικός κόμβος σύνδεσης, κατάστασης και υπηρεσιών της εγκατάστασης.
- **Smart Pro Tunnel 0.1.6** — απομονωμένο outbound tunnel runtime για Managed External URL.

Το **Smart Pro Managed Support** θα προστεθεί στο ίδιο repository πριν από το τελικό public-installation checkpoint, πάνω στην ήδη επαληθευμένη 3.19.1 βάση. Η σταδιακή εισαγωγή γίνεται σκόπιμα ώστε να ελεγχθεί πρώτα η νέα tokenless distribution identity και το Smart Pro System 3.0.0 foundation χωρίς να αλλάξει ο δοκιμασμένος Managed runtime.

## Αρχές vNext

- σταθερό δημόσιο repository URL χωρίς GitHub PAT/token,
- το customer-facing όνομα είναι **Smart Pro System**, ενώ το εσωτερικό add-on slug παραμένει `smart_pro_tools`,
- υποστήριξη connected subscriber, standalone/one-off και unpaired εγκατάστασης,
- καθαρή διάκριση entitlement από πραγματικό runtime,
- secrets δεν ενσωματώνονται στο repository ή στο UI,
- εμπορικές ενέργειες παραμένουν στο Smart Pro Portal.
