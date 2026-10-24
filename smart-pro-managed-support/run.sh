#!/bin/sh
set -eu

VERSION="${SMART_PRO_MANAGED_VERSION:-3.19.1}"
PORT="8098"

umask 077
ulimit -c 0 2>/dev/null || true

echo "===================================================="
echo "  Smart Pro Managed Support"
echo "===================================================="
echo "Κατάσταση: PER-INSTALLATION TARGET RUNTIME + DEDICATED API GATEWAY ${VERSION}"
echo "Το Ingress UI ακούει μόνο στο εσωτερικό port ${PORT}."
echo "Ενεργά: verified per-installation target runtime + unattended renewable leases + dedicated Smart Pro API gateway endpoint."
echo "Broker endpoint: https://api.smart-pro-system.gr/wp-json/smart-pro-remote/v1 — machine-to-machine μόνο. Identity/runtime source παραμένουν TARGET."
echo "Checkpoint 3.19.1: Active Terminal relay termination pilot πάνω στο verified Managed lifecycle (amd64 + aarch64). Η αυτόματη επανασύνδεση χρησιμοποιεί μόνο reuse-only stable identity. Τα ιστορικά εργαλεία παραμένουν κλειδωμένα. Ανενεργά: MeshAgent -install, service/systemd persistence, technician web/Terminal/Files/Desktop authorization."
echo "===================================================="

exec python3 /opt/smart-pro/app.py
