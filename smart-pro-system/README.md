# Smart Pro System 3.0.8

Το Smart Pro System είναι ο τοπικός κόμβος της εγκατάστασης Home Assistant για σύνδεση με το Smart Pro Portal, κατάσταση υπηρεσιών, Guardian, Managed Backup, Managed External URL και ελεγχόμενη τεχνική υποστήριξη.

Η 3.0.8 προσθέτει το πρώτο replacement companion-recovery pilot: όταν ένα verified Portal heartbeat αποδεικνύει ενεργό Managed External URL entitlement και το επίσημο Smart Pro Tunnel λείπει, το Smart Pro System μπορεί να το ανακαλύψει στο Home Assistant store, να το εγκαταστήσει και να κάνει ένα identity-only initial start. Η πραγματική WireGuard/Gateway διαμόρφωση παραμένει αποκλειστικά στον υπάρχοντα signed Control Plane. Το εμφανιζόμενο όνομα αλλάζει σε **Smart Pro System**, ενώ το εσωτερικό slug παραμένει `smart_pro_tools` για τεχνική συνέχεια.

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
