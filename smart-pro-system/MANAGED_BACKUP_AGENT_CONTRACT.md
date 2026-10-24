# Managed Backup Agent Contract — 2.4.52 OVH Primary Upload v1

Adds one controlled signed upload action for the existing `local_verified` job. The exact target is OVHcloud S3 Milan 3-AZ bucket `smartpro-managed-backup-primary-mil`; provider credentials remain local-only in add-on options and are represented to Portal only by bounded booleans. Each upload uses package retention as per-object Object Lock GOVERNANCE retention and is promoted to `primary_verified` only after a full S3 read-back SHA-256 match. Replication, recurring scheduler, delete and restore execution remain OFF.

# Managed Backup Agent Contract — 2.4.40 storage handoff readiness

New read-only heartbeat sub-contract: `smart-pro-managed-backup-storage-handoff-v1`. It proves that the existing local-verified job remains present as a future transfer source while the Portal storage target is explicitly `provider_unconfigured`. No raw backup slug, URL, provider credential, upload grant or bytes leave the installation.

# Smart Pro Tools 2.4.40 — Managed Backup Agent Contract

## Controlled first local backup job
The agent now advertises `local_backup_create`. A job is accepted only through the existing authenticated heartbeat as `smart-pro-managed-backup-local-job-v1`, signed with the already provisioned per-installation Control Plane secret. The job is local-only and must explicitly keep upload/storage/restore-point authority false. The raw Home Assistant backup slug remains local; only a SHA-256 digest and bounded result are returned.

## Scope

Extends the verified Managed Backup node identity/policy/readiness contract with one bounded,
signed local-only Home Assistant backup creation action. Upload/storage authority remains false.

Agent contract: `smart-pro-managed-backup-agent-v1`

Capabilities:
- `node_identity`
- `policy_receive`
- `local_backup_readiness`
- `local_backup_create`

Readiness contract:
- `smart-pro-managed-backup-local-readiness-v1`

## Read-only readiness

The heartbeat readiness block reports only bounded booleans/status values:
- stable Managed Backup node identity present;
- Secure Command Channel reported ready;
- verified Portal Managed Backup policy received;
- daily schedule fields accepted;
- Home Assistant token configured locally (boolean only);
- existing Home Assistant backup inventory endpoint readable;
- bounded backup collection status;
- explicit `data_plane_authorized=false`;
- local checked timestamp.

No Home Assistant Token, backup name, slug, path, size, password, content identifier,
provider credential or raw backup data is emitted.

The Home Assistant backup API signal reuses the already existing read-only Diagnostics
backup inventory collector. This milestone does not add a new backup mutation call.

## Zero-authority boundary

Smart Pro Tools 2.4.40 does **not**:
- create a Managed Backup;
- call `hassio.backup_full` for Managed Backup;
- upload/download a backup;
- connect to storage;
- create a restore point;
- replicate/delete/expire backup data;
- restore Home Assistant;
- add any new Generation-1 Control Plane command;
- open a new inbound port/public endpoint.

Unexpected Portal data-plane authority remains fail-closed and executes no action.

## Hardware replacement

Node identity semantics from 2.4.37 are unchanged. A different node cannot silently
replace an already bound node. Hardware replacement remains a future controlled flow.

## 2.4.54 S3 preflight / failure telemetry
- Controlled primary upload performs one read-only `ListObjectsV2` preflight against the exact configured bucket before local backup bytes are opened for transfer.
- S3 failures are reduced to bounded non-secret error code + operation telemetry; endpoint paths, object bytes, Access Key and Secret Key are never returned to Portal.
- Existing upload, Object Lock, read-back SHA-256 and retry boundaries are unchanged.


## 2.4.55 sequential daily-cycle rule
A new local Managed Backup job ID may replace the previous local job only after the previous job is terminal. If the previous job is local_verified, its matching primary upload must already be primary_verified. This opens sequential daily cycles without granting persistent scheduler authority to Smart Pro Tools.
