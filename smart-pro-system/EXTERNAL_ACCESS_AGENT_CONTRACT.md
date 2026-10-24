# Smart Pro Tools 2.4.43 — External Access Tunnel Enrollment + Gateway Observation Contract

## Tunnel enrollment bridge

- Capability: `tunnel_enrollment_read_only`.
- Source: `/share/smart-pro/tunnel/enrollment.json` written by Smart Pro Tunnel 0.1.4.
- Accepted material: WireGuard **public key only**, Tunnel version, source and bounded timestamp.
- Private key is never read, transported or rendered.
- The heartbeat remains informational only and carries no Tunnel/Gateway/DNS/Caddy/public-ingress write authority.


Agent contract: `smart-pro-external-access-agent-v1`  
Observation contract: `smart-pro-external-access-gateway-observation-v1`

This milestone extends the 2.4.41 identity/readiness foundation with one bounded, non-secret, read-only Gateway Registry observation received only through the existing authenticated Installation heartbeat.

## Local identity

- Dedicated persistent 64-hex External Access node identity remains unchanged.
- The 16-hex proof remains HMAC-derived from the existing per-installation control-plane secret with the `external-access-node-v1` domain separator.
- Private secret material never leaves the installation.

## Gateway observation

The Portal may return a `gateway_observation` only when all of the following are true:

- contract is exactly `smart-pro-external-access-gateway-observation-v1`;
- Installation ID exactly matches the locally paired installation;
- registry SHA-256 is exactly 64 lowercase hex characters;
- registry state is one of `reserved`, `tunnel_pending`, `gateway_ready`, `dns_pending`, `public_pending`, `active`;
- canonical hostname is exactly one opaque 26-character lowercase base32 token under `connect.smart-pro-system.com`;
- peer address is one IPv4 `/32` inside `10.203.0.0/16` and outside the reserved Gateway range `10.203.0.0/24`;
- source is exactly `portal_gateway_registry`;
- `read_only=true` and `runtime_authority=false`;
- observation timestamp is present and not beyond the existing control-plane clock-skew allowance.

Accepted observations are held in memory only. They are echoed on a later heartbeat as bounded status with freshness metadata. They are not persisted as Gateway authority and do not change the local External Access node identity.

## Security boundary

- Existing authenticated Installation heartbeat remains the outer transport.
- No new Secure Command Channel capability is added; the frozen Generation-1 authority digest remains unchanged.
- No Tunnel add-on discovery privilege, Supervisor API permission or cross-add-on filesystem access is added.
- No tunnel daemon is started or controlled by Smart Pro Tools.
- No Gateway endpoint, WireGuard key or credential is accepted.
- No DNS, Caddy, public route, Gateway Registry or router mutation is possible.
- No inbound listener, UPnP or port-forward is created.
- Home Assistant authentication is never bypassed.
- Any advertised runtime authority remains refused fail-closed.

The existing 2.4.41 fields `tunnel_runtime=off`, `gateway_state=not_configured` and `public_route_state=not_issued` continue to describe the Smart Pro Tools runtime boundary itself; the new nested `gateway_observation` is the separate read-only external control-plane view.
