#!/bin/sh

printf '%s\n' "[INFO] Ανάγνωση ρυθμίσεων από το Χρηματοκιβώτιο..."
HA_TOKEN=$(python3 -c "import json; print(json.load(open('/data/options.json')).get('ha_token', ''))")

if [ -n "${SUPERVISOR_TOKEN:-}" ]; then
  printf '%s\n' "[INFO] Διαθέσιμο ασφαλές scoped Home Assistant API credential από το Supervisor."
  printf '%s\n' "[INFO] Δεν απαιτείται χειροκίνητο Home Assistant Long-Lived Access Token."
elif [ -n "$HA_TOKEN" ]; then
  printf '%s\n' "[INFO] Χρήση ρυθμισμένου Home Assistant Token ως compatibility fallback."
else
  printf '%s\n' "[ΠΡΟΕΙΔΟΠΟΙΗΣΗ] Δεν βρέθηκε διαθέσιμο Home Assistant API credential."
fi

printf '%s\n' "[INFO] Τα Home Assistant API credentials παραμένουν μόνο στην πλευρά του server."
printf '%s\n' "[INFO] Εκκίνηση Smart Pro System..."

exec python3 -u app.py
