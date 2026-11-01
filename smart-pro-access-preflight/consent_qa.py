"""Strict one-time, current-process QA consent tokens; no secrets persisted."""
from __future__ import annotations
import hmac
import secrets
import threading
import time
from urllib.parse import urlsplit

APPROVAL_WORD = "ΔΟΚΙΜΗ"
WINDOW_SEC = 180
_lock = threading.RLock()
_issued = {}
_attempted = False


def issue(user_id: str, now=None) -> str:
    now = time.monotonic() if now is None else now
    with _lock:
        for key in list(_issued):
            if _issued[key][1] < now or _issued[key][0] == user_id:
                del _issued[key]
        key = secrets.token_urlsafe(32)
        _issued[key] = (user_id, now + WINDOW_SEC)
        return key


def consume(token: str, user_id: str, confirmation: str, *, now=None) -> bool:
    now = time.monotonic() if now is None else now
    if not isinstance(token, str) or len(token) > 128:
        return False
    with _lock:
        row = _issued.pop(token, None)
        return bool(row and row[1] >= now and hmac.compare_digest(row[0], user_id)
                    and confirmation == APPROVAL_WORD)


def allow_one_attempt() -> bool:
    global _attempted
    with _lock:
        if _attempted:
            return False
        _attempted = True
        return True


def same_origin(headers) -> bool:
    """Same-origin *browser* proof, compatible with Supervisor ingress proxy.

    Host is often an internal proxy authority rather than the origin of the
    iframe in the browser. An exact Origin==Host remains acceptable. When
    proxying rewrites Host, require the browser-only Sec-Fetch-Site header to
    say same-origin. Cross-site or same-site fetches always fail closed.

    This is defense in depth alongside independent trusted Supervisor socket
    peer, fresh Core admin readback, and the one-use CSRF+identity token. Never
    treat browser-supplied forwarding headers as proof.
    """
    origin = headers.get("Origin", "")
    host = headers.get("Host", "")
    site = headers.get("Sec-Fetch-Site", "")
    if not isinstance(origin, str) or not isinstance(host, str) or not isinstance(site, str):
        return False
    if site and site != "same-origin":
        return False
    if not host or any(c in host for c in "\r\n /\t"):
        return False
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or
            not parsed.netloc or parsed.username or parsed.password or
            parsed.path or parsed.query or parsed.fragment or
            origin != parsed.scheme + "://" + parsed.netloc):
        return False
    # A browser may see HA's public origin while the add-on sees the ingress
    # container Host. Only the non-forgeable browser Fetch Metadata can bridge
    # that discrepancy; without it, an exact Origin/Host match is required.
    return origin == parsed.scheme + "://" + host or site == "same-origin"


def attempted() -> bool:
    with _lock:
        return _attempted
