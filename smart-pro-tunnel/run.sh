#!/bin/sh
set -eu

printf '%s\n' "[TUNNEL] Smart Pro Tunnel ${APP_VERSION:-0.0.0} starting."
printf '%s\n' "[TUNNEL] Private key material remains inside the app /data volume and is never printed."

exec python3 -u /tunnel.py
