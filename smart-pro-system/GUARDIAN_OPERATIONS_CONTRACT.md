# Smart Pro Guardian Operations Contract — v2

Smart Pro Tools 2.4.23 keeps Guardian monitoring local and publishes only bounded operational facts over the existing authenticated Portal heartbeat.

## Backward-compatible base fields
- enabled
- status: healthy / attention / disabled / waiting / error
- last_check_at
- offline_count
- low_battery_count

## v2 operational fields
- contract = smart-pro-guardian-v2
- reason_code
- last_successful_check_at
- pending_offline_count
- alerted_offline_count
- retry_pending_count
- active_alert
- last_alert_at
- last_alert_request_code
- last_recovery_at
- last_recovery_count
- last_error_at
- monitoring_scope_count
- email_configured
- email_retry_pending_count
- last_email_sent_at
- last_email_error_at
- check_interval_min
- alert_delay_min
- battery_limit
- low_battery_policy = ha_notification_only

## Delivery contract
An offline incident is not marked alerted until the Portal acknowledges the automatic request. Failed Portal delivery remains queued locally and retries with the same stable event key. Email is independent and retries separately.

## Persistence
Real offline and low-battery state is stored locally in `/data/guardian_state.json` with mode 0600. Virtual safe-test entities are never persisted.

## Device names (opt-in, v2.1)
The heartbeat always carries `device_names_consent` (yes / no / unset) and `device_names_consent_at`.
Only when the customer has explicitly chosen "yes" does it also carry `device_names` = `{offline: [...], low_battery: [...]}`: the Home Assistant friendly names of affected devices, at most 20 in total, 60 characters each, held in memory only. The Portal must ignore names unless consent is `yes` and must delete stored names when consent is `no` or `unset`. Automatic request and email text keeps the bounded `<domain> · ref <hash>` reference.
The choice is made by the customer in the Smart Pro Tools Guardian panel. The technician settings route cannot change it. Default behaviour is controlled by `GUARDIAN_NAMES_DEFAULT_CHOICE` (empty = ask first); changing it requires legal review.

## Privacy boundary
Raw Home Assistant entity IDs stay local. Automatic Guardian request/email text uses a bounded `<domain> · ref <hash>` reference. No credentials, tokens or raw diagnostic payloads are sent by this contract.

## Recovery
Recovery timestamps/counts are reported, but request resolution remains a human/Incident-Engine concern and is not automatic in this milestone.

## Separation of concerns
Guardian produces monitoring signals and alerts. Home Assistant Diagnostics / Incident Engine remain separate systems and will be correlated in a later project.
