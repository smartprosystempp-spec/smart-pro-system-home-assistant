# Smart Pro System 3.0.7

Το Smart Pro System είναι ο τοπικός κόμβος της εγκατάστασης Home Assistant για σύνδεση με το Smart Pro Portal, κατάσταση υπηρεσιών, Guardian, Managed Backup, Managed External URL και ελεγχόμενη τεχνική υποστήριξη.

Η 3.0.7 ενοποιεί την πρόσβαση στο Home Assistant API: σε Home Assistant OS/Supervised χρησιμοποιεί κατά προτεραιότητα το container-scoped Supervisor credential και κρατά το χειροκίνητο long-lived token μόνο ως compatibility fallback. Η διόρθωση καλύπτει Guardian, Diagnostics, Managed Backup readiness, Smart Updates, Vacation Mode και entity loading χωρίς να αλλάζει Portal pairing ή runtime authority. Το εμφανιζόμενο όνομα αλλάζει σε **Smart Pro System**, ενώ το εσωτερικό slug παραμένει `smart_pro_tools` για τεχνική συνέχεια.

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
