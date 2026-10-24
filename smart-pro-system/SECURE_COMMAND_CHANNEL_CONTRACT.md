# Smart Pro Secure Command Channel v1

Contract: `smart-pro-command-channel-v1`

This milestone establishes the authenticated Portal -> Tools command transport. Commands are returned only by the existing installation-token-authenticated heartbeat. Each command is additionally protected by a per-installation HMAC key, short TTL, installation binding, nonce/replay protection and a bounded acknowledgement record.

## Foundation capability

Only `control_plane_probe` / `kind=probe` is accepted in 2.4.25. It is a no-op and cannot alter Guardian, Smart Updates, Vacation Mode, pairing, Managed Support, Home Assistant or secrets.

## Fail closed

Commands with an unknown capability, invalid installation ID, key mismatch, invalid signature, expired/oversized TTL, reused nonce or malformed envelope are rejected and acknowledged as rejected/expired.

## Secrets

The provisioned signing secret is stored only in `/data/control_plane_channel.json` with mode 0600. It is never exposed through the local browser UI or Technician Center heartbeat mirror.


## Milestone 3 — Controlled Guardian Settings

The first non-probe capability is `guardian_settings_manage` with `kind=settings_update`.
It accepts only the `guardian_core` family and exactly these values:

- `check_interval_min` (1–60)
- `alert_delay_min` (1–1440)
- `battery_limit` (1–100)

The signed payload carries both `expected` and `values`. Smart Pro Tools compares the current local state with `expected` before writing. If local state changed after Portal preview, the command fails closed with `guardian_state_conflict`. Successful writes use the existing atomic tech-settings store and are acknowledged only after local read-back matches the requested values.

No other Technician Center setting is remotely writable in 2.4.26.

## Milestone 3B — Guardian Monitoring Scope (2.4.27)

Additional allowed command:

- `kind=settings_update`
- `capability=guardian_scope_manage`
- `payload.family=guardian_scope`

The command contains exact `expected.domains` and `values.domains` lists. Smart Pro Tools validates the HMAC/TTL/nonce/binding first, then rejects stale expected state, unknown/duplicate domains, or an empty desired scope. Only the eight categories visible in the local Technician Center may be changed. The hidden generic `sensor` domain remains untouched. Successful local atomic save + read-back returns `applied · guardian_scope_applied`.


## Milestone 3C — Guardian Controlled Actions (2.4.28)

Allowed signed action capabilities:
- `guardian_safe_test_start` — starts the existing Safe Guardian Test using only the local saved test policy.
- `guardian_safe_test_cancel` — clears only the active virtual Guardian test.
- `guardian_email_test` — sends one technical alert test email using the locally stored SMTP credential.

Portal cannot supply SMTP credentials, arbitrary virtual entity IDs, arbitrary Safe Test timings or a device name.
All action commands retain Installation ID binding, HMAC validation, short TTL, nonce/replay protection and acknowledgement semantics.
Guardian enable/disable and all higher-impact automation controls remain outside this milestone.


## Milestone 4A — Smart Updates Controlled Policy (2.4.29)

Allowed capability: `smart_updates_policy_manage`.

Remote-write fields are strictly limited to update targets, maturity wait, backup wait, evaluation delay, rollback offline threshold and notify-only. The Smart Updates master enable/disable switch remains local/read-only in this milestone. Commands carry both expected and desired policy state and are rejected if the local baseline changed after Portal preview.


## Milestone 4B — Smart Updates Master + Safe Test (2.4.30)

New capabilities:
- `settings_update / smart_updates_master_manage`
- `action / smart_updates_safe_test_run`

Remote master enable is rejected unless local `notify_only` is already true. Safe Test calls only the existing simulation engine and never calls real backup/update/restore services.


## Milestone 5A — Guardian Master + Safe Test Policy (2.4.31)

New settings capabilities:
- `guardian_master_manage`
- `guardian_safe_test_policy_manage`

Guardian master writes use exact expected-state protection and local read-back. Remote OFF is rejected while a real offline Guardian incident exists or while Safe Guardian Test is active. Remote ON requires at least one monitored category.

Safe Guardian Test policy writes are limited to `delay_sec` (3–300), `clear_sec` (5–600) and `send_email`. The policy cannot change while a Safe Guardian Test is active. `send_email=true` requires the SMTP credential to already exist locally; the credential itself never enters command payloads or Portal telemetry. The local Safe Test device name remains local-only.


## Milestone 5B — Vacation Mode Controlled Policy (2.4.32)
- settings_update / vacation_policy_manage
- settings_update / vacation_master_manage
- Raw Vacation entity selections remain local-only.
- Tools performs authoritative runtime guard checks before changes that could affect active Vacation execution.
