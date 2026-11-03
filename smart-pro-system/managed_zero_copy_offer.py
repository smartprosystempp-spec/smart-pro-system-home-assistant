"""Passive, non-authorizing Smart Pro Managed Support enrollment offer handoff.

This runs only in paired Smart Pro System after an authenticated Portal heartbeat.
No identity creation, claims, addon starts or secrets. Shared JSON is metadata.
"""
import json
import os
import re
import secrets
import time
from pathlib import Path

CONTRACT = "smart-pro-managed-zero-copy-offer-v1"
LOCAL_CONTRACT = "smart-pro-managed-zero-copy-local-offer-v1"
DEFAULT_PATH = Path("/share/smart-pro-system/managed-enrollment-offer.json")
_ID_RE = re.compile(r"^ID-[0-9]{5}$")
_REF_RE = re.compile(r"^SPMZ-[A-F0-9]{32}$")
_MAX_TTL = 600


def validate_passive_offer(response, paired_installation_id, now=None):
    now = int(time.time() if now is None else now)
    expected = str(paired_installation_id or "").strip().upper()
    if not _ID_RE.fullmatch(expected) or not isinstance(response, dict):
        return None
    if str(response.get("installation_id", "")).strip().upper() != expected:
        return None
    offer = response.get("managed_zero_copy_offer")
    if not isinstance(offer, dict):
        return None
    if offer.get("contract") != CONTRACT or offer.get("read_only") is not True:
        return None
    if (offer.get("claim_authorized") is not False
            or offer.get("identity_created") is not False
            or offer.get("runtime_authorized") is not False
            or offer.get("technician_access_granted") is not False):
        return None
    if str(offer.get("installation_id", "")).strip().upper() != expected:
        return None
    ref = offer.get("request_ref")
    if not isinstance(ref, str) or not _REF_RE.fullmatch(ref):
        return None
    if offer.get("status") != "pending_handoff":
        return None
    issued = offer.get("issued_at")
    expires = offer.get("expires_at")
    server_time = response.get("server_time")
    if any(type(x) is not int for x in (issued, expires, server_time)):
        return None
    if abs(server_time - now) > 300 or issued > server_time or issued <= 0:
        return None
    if expires <= server_time or expires <= now or expires > issued + _MAX_TTL:
        return None
    if issued > now + 300 or expires > now + _MAX_TTL + 300:
        return None
    return {
        "contract": LOCAL_CONTRACT,
        "installation_id": expected,
        "request_ref": ref,  # Correlation identifier, never a bearer grant
        "issued_at": issued,
        "expires_at": expires,
        "received_at": now,
        "status": "pending_handoff",
        "read_only": True,
        "claim_authorized": False,
        "identity_created": False,
        "runtime_authorized": False,
        "technician_access_granted": False,
    }


def _clear(path):
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def consume_heartbeat_offer(response, paired_installation_id, path=DEFAULT_PATH, now=None):
    """Atomically publish only bounded metadata. No claim/execution handler."""
    path = Path(path)
    record = validate_passive_offer(response, paired_installation_id, now=now)
    if record is None:
        _clear(path)
        return False
    temporary = None
    try:
        path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(temporary, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(record, output, ensure_ascii=False, separators=(",", ":"))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o640)
        return True
    except (OSError, ValueError, TypeError):
        _clear(path)
        return False
    finally:
        if temporary is not None:
            _clear(temporary)
