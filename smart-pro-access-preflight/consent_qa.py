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


def strict_origin(headers) -> bool:
    """Fail-closed browser Origin/Host check for actual account-changing POST.

    The HA 0.3.2 live probe confirmed browser fetch gives valid Origin, same
    incoming Host, and custom action header. The optional Sec-Fetch-Site header
    is missing and therefore MUST NOT be required. A supplied cross-site or
    same-site value, however, is actively rejected.
    """
    values = {}
    for name in ('Origin','Host','Sec-Fetch-Site','X-Smart-Pro-QA-Action'):
        matches = [v for k,v in headers.items() if str(k).lower() == name.lower()]
        if (name != 'Sec-Fetch-Site' and len(matches) != 1 or
            name == 'Sec-Fetch-Site' and len(matches) > 1):
            return False
        values[name] = matches[0] if matches else None
    origin, host = values['Origin'], values['Host']
    site, action = values['Sec-Fetch-Site'], values['X-Smart-Pro-QA-Action']
    if not isinstance(origin,str) or not isinstance(host,str) or action != 'v1':
        return False
    if site is not None and site != 'same-origin':
        return False
    if not host or any(c in host for c in '\r\n /\t'):
        return False
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    return bool(parsed.scheme in ('http','https') and parsed.netloc == host and
                parsed.hostname and not parsed.username and not parsed.password and
                not parsed.path and not parsed.query and not parsed.fragment and
                origin == parsed.scheme + '://' + host)


def attempted() -> bool:
    with _lock:
        return _attempted
