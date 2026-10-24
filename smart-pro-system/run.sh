#!/bin/sh

printf '%s\n' "[INFO] Ανάγνωση ρυθμίσεων από το Χρηματοκιβώτιο..."
HA_TOKEN=$(python3 -c "import json; print(json.load(open('/data/options.json')).get('ha_token', ''))")

if [ -z "$HA_TOKEN" ]; then
  printf '%s\n' "[ΣΦΑΛΜΑ] Προσοχή: Το Token στο Χρηματοκιβώτιο βρέθηκε ΚΕΝΟ!"
else
  printf '%s\n' "[INFO] Το Token διαβάστηκε με επιτυχία από τη Διαμόρφωση."
fi

printf '%s\n' "[INFO] Το Home Assistant Token παραμένει μόνο στην πλευρά του server."
printf '%s\n' "[INFO] Εκκίνηση Smart Pro System..."

exec python3 -u app.py
