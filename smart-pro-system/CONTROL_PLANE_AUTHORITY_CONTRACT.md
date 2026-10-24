# Smart Pro Control Plane Authority Contract v1

## Contract
`smart-pro-control-plane-capabilities-v1`

## Purpose
Read-only declaration of the exact Generation-1 Portal -> Smart Pro Tools authority surface. The manifest is emitted inside the existing authenticated `smart-pro-technician-center-v1` heartbeat and contains no secret material.

## Source of truth
`CONTROL_PLANE_ALLOWED_CAPABILITIES` is shared by:
1. the Tools command executor allow-list, and
2. the capability manifest.

The Portal therefore does not have to infer current command support only from a Tools version number.

## Generation-1 remote command families
- control_plane_probe
- guardian_policy
- guardian_scope
- guardian_actions
- guardian_master
- guardian_safe_test_policy
- smart_updates_policy
- smart_updates_master
- smart_updates_safe_test
- vacation_policy
- vacation_master

## Deliberate local-only boundaries
- SMTP credentials
- Safe Guardian Test device name
- raw Vacation entity selections
- Managed Support manual pause
- pairing / recovery identity
- Home Assistant token
- MeshCentral secrets
- privileged recovery / destructive actions
- local Mesh banner presentation
- manual remote banner
- legacy subscription fallback fields

## Security meaning
The manifest is informational and grants no authority by itself. Every actual command still requires the independent `smart-pro-command-channel-v1` controls: authenticated Installation heartbeat, per-installation HMAC key, Installation/key binding, short TTL, nonce/replay protection, preview/confirmation where applicable, strict capability allow-list, local validation and read-back acknowledgement.


## Generation-1 frozen baseline — 2.4.34
- Freeze contract: `smart-pro-control-plane-freeze-v1`
- Freeze ID: `generation-1-20260927`
- Expected authority digest: `7aa414919c982e10c24040f463c5c5e97ada9269685058e1c505d074d00433c2`
- The digest is calculated from the exact executor allow-list, family/local-only boundaries and core command security envelope.
- No new executable authority is introduced by the freeze metadata.
