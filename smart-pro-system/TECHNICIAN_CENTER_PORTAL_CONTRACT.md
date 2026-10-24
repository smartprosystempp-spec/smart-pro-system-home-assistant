# Smart Pro Technician Center Portal Contract v1

## Purpose
Read-only mirror of selected local Smart Pro Tools Technician Center settings into the authorized Admin Portal.

## Contract
`smart-pro-technician-center-v1`

## Security boundary
- Outbound only through the existing authenticated Installation heartbeat.
- Read-only: no Portal command is accepted in 2.4.24.
- No SMTP password, Portal installation token, MeshCentral secret, Home Assistant token, local technician PIN, raw Home Assistant entity IDs or selected Vacation entity IDs are sent.
- Vacation device selections are represented only as counts.
- Monitoring categories are represented only as safe Home Assistant domain names.

## Sections
- `general`: Portal/subscription/local operational configuration flags.
- `guardian`: Guardian policy and safe-test defaults.
- `automations`: Smart Updates and Vacation-mode policy summaries.
- `control_plane`: Generation-1 authority manifest (`smart-pro-control-plane-capabilities-v1`) with bounded family/capability IDs and deliberate local-only boundaries.

## Authority evolution
The separate signed-command contract is now production-verified. Starting with Smart Pro Tools 2.4.33, the read-only `control_plane` manifest declares the exact Generation-1 authority surface while command execution remains enforced independently by `smart-pro-command-channel-v1`. The manifest contains no secrets and does not itself grant authority.


## Generation-1 freeze (2.4.34)
The capability manifest also reports `smart-pro-control-plane-freeze-v1`, freeze ID `generation-1-20260927` and a SHA-256 authority digest. The digest is informational/integrity metadata only; command execution still requires the independent signed command channel and Tools-side enforcement.
