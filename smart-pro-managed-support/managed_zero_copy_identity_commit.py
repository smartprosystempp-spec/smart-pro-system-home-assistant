"""Staged Managed zero-copy identity persistence / ACK payload.

DO NOT wire to any HTTP handler, heartbeat thread or runtime startup until the
Broker's authenticated commit/ACK transport and Admin approval are released.
A candidate alone is never authority: verify live Broker heartbeat first.
Never mutate or replace an existing identity; never launch MeshAgent.
"""
import json
import os
import re
import secrets
import stat
import time
from pathlib import Path

IDENTITY_PATH = Path("/data/managed-identity.json")
RECEIPT_CONTRACT = "smart-pro-managed-zero-copy-private-receipt-v1"
ACK_CONTRACT = "smart-pro-managed-zero-copy-identity-ack-v1"
_ID = re.compile(r"^ID-[0-9]{5}$")
_REF = re.compile(r"^SPMZ-[A-F0-9]{32}$")
_NODE = re.compile(r"^SPMN-[A-F0-9]{32}$")
_SECRET = re.compile(r"^SPMS-[A-Za-z0-9_-]{43}$")
_HEX = re.compile(r"^[a-f0-9]{64}$")


def _read_secure(path):
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o077 or info.st_size < 16
                or info.st_size > 16384):
            return None
        def unique(pairs):
            data = {}
            for key, value in pairs:
                if key in data:
                    raise ValueError("duplicate key")
                data[key] = value
            return data
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
        return data if isinstance(data, dict) else None
    except (FileNotFoundError, OSError, UnicodeError, ValueError):
        return None


def _safe_receipt(candidate):
    if not isinstance(candidate, dict):
        return None
    iid, ref = candidate.get("installation_id"), candidate.get("request_ref")
    node, secret = candidate.get("node_id"), candidate.get("node_secret")
    digest = candidate.get("original_envelope_sha256")
    if (not isinstance(iid, str) or not _ID.fullmatch(iid)
            or not isinstance(ref, str) or not _REF.fullmatch(ref)
            or not isinstance(node, str) or not _NODE.fullmatch(node)
            or not isinstance(secret, str) or not _SECRET.fullmatch(secret)
            or not isinstance(digest, str) or not _HEX.fullmatch(digest)
            or candidate.get("verified_cryptographically") is not True
            or candidate.get("delivery_proof_verified") is not True
            or candidate.get("server_authorized") is not False
            or candidate.get("identity_persisted") is not False
            or candidate.get("runtime_authorized") is not False):
        return None
    return {"installation_id": iid, "request_ref": ref, "node_id": node,
            "node_secret": secret, "envelope_sha256": digest}


def _valid_live_broker_response(reply, record, now):
    if not isinstance(reply, dict):
        return False
    if reply.get("node_id") != record["node_id"] or reply.get("installation_ref") != record["installation_id"]:
        return False
    auth = reply.get("server_authorization")
    if not isinstance(auth, dict):
        return False
    valid_until = auth.get("valid_until")
    if (type(auth.get("schema_version")) is not int or auth["schema_version"] != 1
            or auth.get("installation_id") != record["installation_id"]
            or auth.get("authorized") is not True
            or type(valid_until) is not int or valid_until <= now + 15
            or auth.get("portal_paired") is not True
            or auth.get("managed_entitlement") is not True
            or auth.get("subscription_status") != "active"
            or auth.get("managed_relationship_state") != "enrolled"
            or auth.get("remote_access") is not False
            or auth.get("meshcentral") is not False):
        return False
    return True


def _valid_fresh_policy(policy_snapshot, iid):
    if not isinstance(policy_snapshot, dict) or policy_snapshot.get("allowed_local") is not True:
        return False
    raw = policy_snapshot.get("policy")
    if not isinstance(raw, dict) or raw.get("installation_id") != iid or raw.get("manual_pause") is True:
        return False
    ent = raw.get("entitlement")
    sub = raw.get("subscription")
    health = raw.get("health")
    if (not isinstance(ent, dict) or ent.get("managed_remote_support") is not True
            or not isinstance(sub, dict) or sub.get("status") != "active"
            or sub.get("services_active") is not True or sub.get("using_cached_state") is not False
            or not isinstance(health, dict) or health.get("portal_paired") is not True
            or health.get("portal_sync_healthy") is not True):
        return False
    return True


def _identity_matches(stored, record):
    if not isinstance(stored, dict):
        return False
    receipt = stored.get("zero_copy_receipt")
    return (isinstance(receipt, dict) and receipt.get("contract") == RECEIPT_CONTRACT
            and receipt.get("request_ref") == record["request_ref"]
            and receipt.get("envelope_sha256") == record["envelope_sha256"]
            and stored.get("installation_id") == record["installation_id"]
            and stored.get("node_id") == record["node_id"]
            and stored.get("node_secret") == record["node_secret"])


def commit_verified_identity(candidate, broker_reply, policy_snapshot, *,
                             identity_path=IDENTITY_PATH, now=None):
    """Persist only after live HTTPS Broker heartbeat readback and local policy.

    Caller must obtain broker_reply from the existing /managed/heartbeat using
    candidate credentials in memory; this function never performs HTTP itself.
    Atomic publication is link(no-overwrite) + parent directory fsync. Crashes
    before link leave no public identity; crashes afterwards are idempotent.
    """
    now = int(time.time() if now is None else now)
    record = _safe_receipt(candidate)
    if (record is None or not _valid_live_broker_response(broker_reply, record, now)
            or not _valid_fresh_policy(policy_snapshot, record["installation_id"])):
        return {"ok": False, "state": "verification_denied"}
    target = Path(identity_path)
    existing = _read_secure(target)
    if target.is_symlink() or target.exists():
        return ({"ok": True, "state": "already_committed"} if _identity_matches(existing, record)
                else {"ok": False, "state": "identity_conflict"})

    content = {
        "node_id": record["node_id"], "node_secret": record["node_secret"],
        "installation_id": record["installation_id"], "paired_at": now,
        "zero_copy_receipt": {
            "contract": RECEIPT_CONTRACT, "request_ref": record["request_ref"],
            "envelope_sha256": record["envelope_sha256"], "committed_at": now,
            "delivery_acknowledged": False,
        },
    }
    temporary = None
    linked = False
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + "." + secrets.token_hex(12) + ".tmp")
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(temporary, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(content, handle, separators=(",", ":"), ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, target, follow_symlinks=False)
        linked = True
        dirflags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        dirfd = os.open(target.parent, dirflags)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        return {"ok": True, "state": "committed"}
    except FileExistsError:
        existing = _read_secure(target)
        return ({"ok": True, "state": "already_committed"} if _identity_matches(existing, record)
                else {"ok": False, "state": "identity_conflict"})
    except (OSError, ValueError, TypeError):
        # Do not remove the published target after an unknown fsync outcome.
        return {"ok": False, "state": "commit_unknown" if linked else "storage_failed"}
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def authenticated_ack_payload(identity_path=IDENTITY_PATH, expected_installation=None):
    """Build an in-memory ACK from private persisted identity, never send it.

    Future Broker endpoint MUST validate node_secret against node's hash, the
    immutable ledger's node/ref/digest and a fresh server auth check. ACK is
    idempotent; no technician privileges or runtime grants.
    """
    data = _read_secure(Path(identity_path))
    if not isinstance(data, dict):
        return None
    iid, ref, node, secret = (data.get("installation_id"), None,
                            data.get("node_id"), data.get("node_secret"))
    receipt = data.get("zero_copy_receipt")
    if isinstance(receipt, dict):
        ref = receipt.get("request_ref")
        digest = receipt.get("envelope_sha256")
    else:
        return None
    if (iid != expected_installation or not isinstance(iid, str) or not _ID.fullmatch(iid)
            or not isinstance(ref, str) or not _REF.fullmatch(ref)
            or not isinstance(node, str) or not _NODE.fullmatch(node)
            or not isinstance(secret, str) or not _SECRET.fullmatch(secret)
            or receipt.get("contract") != RECEIPT_CONTRACT
            or not isinstance(digest, str) or not _HEX.fullmatch(digest)):
        return None
    return {
        "contract": ACK_CONTRACT, "installation_id": iid,
        "request_ref": ref, "node_id": node, "node_secret": secret,
        "envelope_sha256": digest, "identity_persisted": True,
        "runtime_authorized": False, "technician_access_granted": False,
    }
