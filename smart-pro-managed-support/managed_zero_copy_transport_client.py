"""Staged exact-origin Broker Zero-Copy HTTP adapter; no runtime handler wired.

Only a read-only, request-bound recipient discovery/recovery/ACK transport.
A valid ciphertext candidate is NOT identity authority. Production coordinator
must get fresh node heartbeat and local policy, then commit, then ACK.

No automatic retries for unknown issuance or post-commit outcomes. Never sends
a secret over redirects, logs or alternate hosts.
"""
import json
import re
import urllib.error
import urllib.request

from managed_zero_copy_receiver import _delivery_context_ok
from managed_zero_copy_delivery import prove_receiver_challenge, verify_original_delivery
from managed_zero_copy_identity_commit import authenticated_ack_payload

BROKER_ORIGIN = "https://api.smart-pro-system.gr"
BROKER_PREFIX = "/wp-json/smart-pro-remote/v1/managed/zero-copy/"
ENROLL_CONTRACT = "smart-pro-managed-zero-copy-"
HEX64 = re.compile(r"^[a-f0-9]{64}$")
MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 8192


class DeliveryUnavailable(Exception):
    """Safe generic outcome: never include transport response or credentials."""


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DeliveryUnavailable("redirect_denied")


def _unique_keys(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("duplicate key")
        data[key] = value
    return data


def _post_contract(endpoint, payload, *, transport=None):
    if endpoint not in ("delivery/challenge", "delivery/fetch", "identity/ack"):
        raise DeliveryUnavailable("operation_denied")
    if not isinstance(payload, dict):
        raise DeliveryUnavailable("request_invalid")
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if not 10 <= len(body) <= MAX_REQUEST_BYTES:
        raise DeliveryUnavailable("request_invalid")
    target = BROKER_ORIGIN + BROKER_PREFIX + endpoint
    if transport is not None:
        # Test-only injected exact request transport, never used by runtime.
        try:
            result = transport(endpoint, payload)
        except Exception:
            raise DeliveryUnavailable("transport_failed") from None
        if not isinstance(result, dict):
            raise DeliveryUnavailable("response_invalid")
        return result
    req = urllib.request.Request(target, method="POST", data=body, headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "SmartProManaged-ZeroCopy-Staged",
    })
    opener = urllib.request.build_opener(_RejectRedirect())
    try:
        with opener.open(req, timeout=12) as resp:
            if resp.status != 200:
                raise DeliveryUnavailable("http_denied")
            if not str(resp.headers.get("Content-Type", "")).lower().startswith("application/json"):
                raise DeliveryUnavailable("response_invalid")
            if resp.geturl() != target:
                raise DeliveryUnavailable("origin_mismatch")
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise DeliveryUnavailable("response_too_large")
            result = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_keys)
            if not isinstance(result, dict):
                raise DeliveryUnavailable("response_invalid")
            return result
    except (OSError, ValueError, UnicodeError, urllib.error.URLError):
        raise DeliveryUnavailable("transport_failed") from None


def _common(context, architecture, operation, now):
    if architecture not in ("amd64", "aarch64") or not isinstance(context, dict):
        return None
    iid, ref, public = (context.get("installation_id"), context.get("request_ref"),
                        context.get("receiver_public_key_hex"))
    if (not isinstance(iid, str) or not isinstance(ref, str)
            or not isinstance(public, str) or not HEX64.fullmatch(public)
            or not _delivery_context_ok(context, iid, now)):
        return None
    return {
        "contract": ENROLL_CONTRACT + operation + "-request-v1",
        "installation_id": iid, "request_ref": ref,
        "receiver_public_key_hex": public,
        "architecture": architecture,
        "read_only": True, "claim_authorized": False,
        "identity_created": False, "runtime_authorized": False,
        "technician_access_granted": False,
    }


def request_challenge(context, architecture, *, transport=None, now=None):
    import time
    now = int(time.time() if now is None else now)
    payload = _common(context, architecture, "challenge", now)
    if payload is None:
        return None
    try:
        answer = _post_contract("delivery/challenge", payload, transport=transport)
    except DeliveryUnavailable:
        return None
    # Caller MUST decrypt and verify the challenge before trusting any returned data.
    if (answer.get("contract") != "smart-pro-managed-zero-copy-delivery-challenge-v1"
            or answer.get("installation_id") != payload["installation_id"]
            or answer.get("request_ref") != payload["request_ref"]
            or answer.get("receiver_public_key_hex") != payload["receiver_public_key_hex"]
            or answer.get("architecture") != architecture
            or answer.get("identity_created") is not False
            or answer.get("runtime_authorized") is not False
            or answer.get("technician_access_granted") is not False):
        return None
    return answer


def retrieve_original_candidate(context, architecture, challenge, *,
                                transport=None, key_path=None, now=None):
    import time
    now = int(time.time() if now is None else now)
    public_request = _common(context, architecture, "fetch", now)
    if public_request is None:
        return None
    proof_kw = {"now": now}
    if key_path is not None:
        proof_kw["key_path"] = key_path
    proof = prove_receiver_challenge(
        challenge, context, context["installation_id"], architecture, **proof_kw)
    if not isinstance(proof, dict) or not isinstance(proof.get("proof_hex"), str):
        return None
    payload = dict(public_request, proof_hex=proof["proof_hex"])
    try:
        answer = _post_contract("delivery/fetch", payload, transport=transport)
    except DeliveryUnavailable:
        return None
    kw = {"now": now}
    if key_path is not None:
        kw["key_path"] = key_path
    return verify_original_delivery(
        answer, proof, context, context["installation_id"], architecture, **kw)


def transmit_persisted_ack(installation_id, *, transport=None, identity_path=None):
    kw = {"expected_installation": installation_id}
    if identity_path is not None:
        kw["identity_path"] = identity_path
    payload = authenticated_ack_payload(**kw)
    if not isinstance(payload, dict):
        return None
    try:
        response = _post_contract("identity/ack", payload, transport=transport)
    except DeliveryUnavailable:
        return None
    if (response.get("contract") != "smart-pro-managed-zero-copy-identity-ack-v1"
            or response.get("installation_id") != installation_id
            or response.get("request_ref") != payload["request_ref"]
            or response.get("status") != "verified"
            or response.get("runtime_authorized") is not False
            or response.get("technician_access_granted") is not False):
        return None
    return {
        "contract": "smart-pro-managed-zero-copy-ack-result-v1",
        "installation_id": installation_id,
        "request_ref": payload["request_ref"],
        "status": "verified",
        "already_verified": response.get("already_verified") is True,
        "identity_persisted": True,
        "runtime_authorized": False,
        "technician_access_granted": False,
    }
