# Smart Pro Tools 2.4.35 — Service Access Enforcement Contract

Portal contract: `smart-pro-service-access-v1`

## Authoritative rules
- Trial / Active / Grace may enable platform services only when the exact entitlement is true.
- Expired / Suspended / Trial-expired / inactive platform state disable subscription-gated services.
- Portal verification must remain valid; cached state is accepted only inside the existing verification tolerance.
- Managed enrollment/relationship remains independent and is not gated by this contract.

## Enforced in 2.4.35
- Guardian runtime + Safe Guardian Test -> `guardian_monitoring`
- Backup / Health diagnostics -> `backup_health`
- Smart Updates runtime + Safe Smart Updates Test -> `update_guidance`
- Normal customer support request UI + local request endpoint -> `support_requests`
- Generic subscription-gated runtime (currently Vacation Mode) -> `platform_services_active`

## Safety
- Does not add any new Control Plane capability.
- Does not mutate subscription state, payment state, wallet, pairing or Managed enrollment.
- Does not silently uninstall or de-pair anything when access becomes inactive.
