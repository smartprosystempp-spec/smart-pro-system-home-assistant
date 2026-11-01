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
    """Require real browser Origin to match Host; tokens still bind authority."""
    origin = headers.get("Origin", "")
    host = headers.get("Host", "")
    if not isinstance(origin, str) or not isinstance(host, str):
        return False
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    return bool(parsed.scheme in ("http", "https") and parsed.netloc == host
                and not parsed.path and not parsed.query and not parsed.fragment)


def attempted() -> bool:
    with _lock:
        return _attempted
