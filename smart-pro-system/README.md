# Smart Pro System 3.0.11

Το Smart Pro System είναι ο τοπικός κόμβος της εγκατάστασης Home Assistant για σύνδεση με το Smart Pro Portal, κατάσταση υπηρεσιών, Guardian, Managed Backup, Managed External URL και ελεγχόμενη τεχνική υποστήριξη.

Η 3.0.11 είναι προσωρινό **read-only diagnostic checkpoint** για το replacement Tunnel recovery. Προσθέτει ένα sanitized Store-contract endpoint και παγώνει προσωρινά την αυτόματη εγκατάσταση/εκκίνηση του Tunnel, ώστε να δούμε το πραγματικό Supervisor Store candidate/repository/version shape της QA6 χωρίς mutation. Η 3.0.10 παραμένει η τελευταία functional recovery βάση. Το εμφανιζόμενο όνομα είναι **Smart Pro System**, ενώ το εσωτερικό slug παραμένει `smart_pro_tools` για τεχνική συνέχεια.

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
