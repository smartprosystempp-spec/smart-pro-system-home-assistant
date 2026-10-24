## 3.19.1 — Active Terminal Relay Termination Pilot

The existing persistent-runtime watch now consumes a Broker monotonic termination generation. When a newer generation arrives after verified Terminal rights have returned to zero, only the foreground MeshAgent process group is terminated and immediately relaunched with the same persisted stable identity. This closes already-open MeshCentral Terminal relays while keeping the add-on and Managed enrollment alive. The pilot is intentionally coarse-grained: recycling the foreground MeshAgent can interrupt any other relay on the same node, so validation starts with Terminal as the only active capability.

# Smart Pro Managed Support 3.18.2

Το **Smart Pro Managed Support** είναι το πρόσθετο μόνιμης, ελεγχόμενης υποστήριξης του Smart Pro System για Home Assistant.

Η 3.18.2 είναι μικρή έκδοση **multi-architecture compatibility** πάνω στην επαληθευμένη 3.18.1. Το ίδιο add-on δηλώνεται πλέον για **amd64 και aarch64**, ώστε η σταθερή Managed γραμμή να μπορεί να χρησιμοποιηθεί τόσο στο QA VM όσο και σε Home Assistant Green/ARM64 εγκαταστάσεις χωρίς ξεχωριστό fork.

## Τι αλλάζει
- Το Home Assistant add-on metadata υποστηρίζει `amd64` και `aarch64`.
- Το stable 3.18 lifecycle gate μεταφέρεται στην 3.18.2 ώστε η αυτόματη επανασύνδεση και τα explicit Enable/Pause controls να λειτουργούν κανονικά μετά το version bump.
- Το Docker build-version fallback ενημερώνεται στην 3.18.2.
- Η υπάρχουσα runtime υλοποίηση συνεχίζει να επιλέγει και να επαληθεύει το σωστό MeshAgent binary ανά architecture.

## Τι δεν αλλάζει
- Δεν γίνεται re-pair ή reseed.
- Δεν δημιουργείται νέο MeshCentral node από το update.
- Δεν αλλάζει το per-installation target group ή το persisted MeshAgent identity.
- Δεν αλλάζει η λογική renewable leases / reconnect / Broker authorization.
- Δεν αλλάζουν MeshCentral permissions.
- Δεν χρησιμοποιείται MeshAgent `-install`.
- Δεν δημιουργείται service/systemd persistence.
- Web / Terminal / Files / Desktop για τεχνικό παραμένουν **NOT AUTHORIZED**.
- Τα ιστορικά first-device εργαλεία παραμένουν αρχειοθετημένα και κλειδωμένα· τα παλιά amd64-only checkpoints δεν γίνονται multi-arch.

Η έκδοση προορίζεται για **update-in-place**. Δεν γίνεται uninstall, διαγραφή `/data`, νέο pairing ή χειροκίνητη μετακίνηση/διαγραφή MeshCentral node.
