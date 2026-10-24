# Smart Pro Managed Network Contract v1

## Σκοπός

Το Smart Pro Tools 2.4.7 παράγει ένα ελάχιστο, μη-μυστικό network-discovery contract για το Smart Pro Managed Support. Η έκδοση αυτή κάνει μόνο discovery. Δεν ανοίγει Router Web, δεν δημιουργεί proxy και δεν εκτελεί HTTP/HTTPS probes.

## Αρχείο

Το contract γράφεται ατομικά στο:

`/share/smart-pro-system/managed-network.json`

Το Smart Pro Managed Support πρέπει να χαρτογραφεί το ίδιο Home Assistant `share` read-only.

## Πηγή discovery

Το Smart Pro Tools ήδη εκτελείται με `host_network: true`. Η 2.4.7 διαβάζει read-only το Linux `/proc/net/route`, επιλέγει μόνο route με:

- destination `0.0.0.0/0`,
- flags `UP + GATEWAY`,
- μη μηδενικό gateway,
- gateway αυστηρά μέσα σε RFC1918 IPv4 (`10/8`, `172.16/12`, `192.168/16`).

Αν υπάρχουν πολλαπλά έγκυρα default routes, επιλέγεται deterministically το χαμηλότερο metric.

## Contract fields

- `contract_id = smart-pro-managed-network-v1`
- `network_version = 1`
- `generated_at`
- `source.addon`, `source.addon_version`, `source.discovery`
- `installation_id`
- `state = ready | unavailable`
- `reason_code`
- `router_candidate.interface`
- `router_candidate.gateway_ipv4`
- `router_candidate.metric`
- `liveness.refresh_seconds`, `lease_seconds`, `lease_until`
- `health.host_network_expected`, `route_source_readable`

## Fail-closed reason codes

- `private_default_gateway_ready`
- `installation_id_missing`
- `private_default_gateway_not_found`
- `route_read_error`

Όταν `state != ready`, το `router_candidate` είναι `null`.

## Security boundary

Το contract δεν περιέχει και δεν πρέπει να περιέχει:

- Home Assistant token,
- Supervisor token,
- Portal installation token,
- MeshCentral credentials / `.msh`,
- router username/password,
- browser-provided target IP/URL,
- session URLs/tickets.

Η ύπαρξη gateway candidate δεν αποτελεί από μόνη της authorization για Router Web. Το μελλοντικό Router Compatibility layer πρέπει επιπλέον να απαιτεί Managed authorization, freshness/Installation-ID binding και δικό του αυστηρό target/profile allowlist.
