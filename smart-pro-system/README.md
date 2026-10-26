# Smart Pro System 3.0.12

Το Smart Pro System είναι ο τοπικός κόμβος της εγκατάστασης Home Assistant για σύνδεση με το Smart Pro Portal, κατάσταση υπηρεσιών, Guardian, Managed Backup, Managed External URL και ελεγχόμενη τεχνική υποστήριξη.

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
