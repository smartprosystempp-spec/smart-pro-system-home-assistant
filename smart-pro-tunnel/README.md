Smart Pro Tunnel 0.1.6 uses the exact internal Home Assistant Core target discovered by Smart Pro Tools through the Supervisor API; the Tunnel itself receives no Supervisor/Home Assistant credential.

# Smart Pro Tunnel

Isolated outbound private-tunnel runtime for the Smart Pro Managed External URL project.

## 0.1.4 — Public-only Enrollment Material Bridge

Smart Pro Tunnel publishes its **public** WireGuard identity into `/share/smart-pro/tunnel/enrollment.json` so the paired Smart Pro Tools agent can forward that material through its authenticated Portal heartbeat. The private key never leaves `/data/wireguard/private.key`. This bridge grants no runtime authority and performs no Gateway/DNS/Caddy/public-ingress mutation.

## 0.1.3 — Controlled Boot Policy Enablement

Builds directly on the live-verified 0.1.2 private Home Assistant TCP proxy canary. This milestone changes only the Home Assistant app boot policy from `manual_only` to user-selectable `manual`, so the operator can explicitly enable **Start on boot** after verification.

Safety boundaries:

- app still defaults to manual boot after install/update;
- **Start on boot** becomes user-selectable instead of Supervisor-blocked;
- Watchdog remains operator-controlled and is not enabled by this update;
- WireGuard identity and `/data` persistence are unchanged;
- tunnel runtime, route scope, health endpoint, HA target probe and private proxy logic are byte-identical to 0.1.2;
- no new network permissions, host ports, Home Assistant/Supervisor API access, NAT or IP forwarding;
- no public hostname, DNS or Caddy settings are embedded in the app.

## 0.1.2 — Private Home Assistant TCP Proxy Canary

Builds directly on the live-verified 0.1.1 target probe. This milestone adds an optional private TCP proxy that binds only to the installation WireGuard /32 and forwards byte-for-byte to `homeassistant:8123`.

Security boundaries:

- separate app from Smart Pro Tools;
- `NET_ADMIN` only on this tunnel app;
- `/dev/net/tun` remains the only mapped device;
- no `host_network`;
- no host ports;
- no Supervisor/Home Assistant API permission or token;
- no IP forwarding or NAT;
- WireGuard private key remains only in `/data/wireguard/private.key`, mode `0600`, and is never printed;
- only `10.203.0.1/32` is routed through `wg0`;
- health endpoint remains tunnel-only on TCP 8788;
- optional private proxy binds only to the peer tunnel IP on TCP 18123;
- proxy accepts only source `10.203.0.1` from the External Gateway;
- proxy performs no authentication bypass and injects no headers;
- no public URL, DNS publication, public ingress, router mutation or customer port-forward;
- `private_proxy_enabled` defaults to `false`;
- app remains `manual_only`.
