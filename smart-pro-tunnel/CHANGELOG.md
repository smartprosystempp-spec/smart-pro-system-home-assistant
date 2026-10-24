## 0.1.6 — Supervisor-discovered Core target + protocol-neutral readiness
- Adds explicit internal Home Assistant target host/port/SSL options written only by Smart Pro Tools orchestration.
- Removes the hard-coded `homeassistant:8123` runtime dependency for Managed External URL activation.
- Uses a TCP-only readiness probe because the private proxy is raw TCP and must work for both HTTP and HTTPS Core configurations.
- Keeps the proxy bound only to the installation WireGuard /32 and restricted to gateway source 10.203.0.1.
- Adds no Home Assistant/Supervisor credential to the Tunnel and no DNS, public ingress, NAT or IP forwarding.

## 0.1.5 — Safe runtime status bridge
- Publishes a sanitized shared runtime-status record for Smart Pro Tools.
- No private key, Gateway secret, DNS authority or public URL is exposed.

# Changelog

## 0.1.4

- Publishes a bounded public-only WireGuard enrollment record to `/share/smart-pro/tunnel/enrollment.json` for Smart Pro Tools 2.4.43.
- Record contains only contract/version/public key/source/timestamp and explicit `private_key_exposed=false` / `runtime_authority=false`.
- Private WireGuard key remains only in `/data/wireguard/private.key` mode 0600 and is never copied to `/share`, Portal, logs or UI by this bridge.
- Enrollment publication is read-only metadata and does not change WireGuard peer configuration, Gateway, DNS, Caddy, nftables, public ingress or Home Assistant authentication.
- Failure to publish the metadata does not stop an already-working tunnel; automated provisioning preflight simply remains unavailable.

## 0.1.3

- Changes app boot policy from `manual_only` to user-selectable `manual`.
- Keeps boot disabled by default while allowing the operator to enable **Start on boot** explicitly after QA.
- Does not enable Watchdog automatically.
- Preserves WireGuard identity, tunnel/proxy runtime, route scope, permissions and `/data` state from 0.1.2.
- No new public ingress, DNS, Caddy, NAT, IP forwarding, host networking or API permissions.
- Smart Pro Tools 2.4.41 remains byte-identical.

## 0.1.2

- Adds optional tunnel-only TCP proxy on `10.203.1.1:18123` to `homeassistant:8123`.
- Proxy is disabled by default and requires explicit `private_proxy_enabled: true`.
- Listener binds only to the WireGuard peer /32 and accepts only gateway source `10.203.0.1`.
- No Home Assistant token, API permission, auth bypass or header injection.
- No public URL, DNS, NAT, IP forwarding, host networking or host port.
- Preserves the 0.1.1 target probe and the persistent WireGuard identity.
- Removes accidental packaged Python `__pycache__` artifacts from 0.1.1 packaging.
- Smart Pro Tools 2.4.41 remains byte-identical.

## 0.1.1

- Adds read-only Home Assistant target reachability probe to `homeassistant:8123`.
- Probe uses no Home Assistant token and requests no Supervisor/Home Assistant API permission.
- Health status adds bounded target-probe state and HTTP status code only.
- Does not proxy Home Assistant and does not publish any URL.
- Preserves WireGuard identity, route scope, permissions and manual-only lifecycle from 0.1.0.
- Smart Pro Tools 2.4.41 remains byte-identical.

## 0.1.0

- Adds isolated Smart Pro Tunnel app as a second app in the existing repository.
- Generates and persists a dedicated WireGuard keypair locally.
- Adds controlled outbound WireGuard client runtime with kernel interface first and `wireguard-go` fallback.
- Limits tunnel routing to `10.203.0.1/32` only.
- Adds private tunnel-only `/health` endpoint on TCP 8788.
- Adds safe local status persistence without private key material.
- Keeps Smart Pro Tools 2.4.41 byte-identical.
- No Home Assistant proxy, public URL, DNS, ingress, NAT, IP forwarding or router mutation.
