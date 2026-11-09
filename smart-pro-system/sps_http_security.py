"""Smart Pro System local HTTP ingress boundary (3.0.34).

Only HA Supervisor Ingress can reach the browser endpoints.  This is a distinct
boundary from the privileged Technician Session and the protected HA-admin
handoff, whose existing authorizers remain unchanged.
"""
from datetime import date, datetime, timedelta
import ipaddress
import re
import secrets
import threading
import time

INGRESS_PEER = ipaddress.ip_address('172.30.32.2')
HA_USER_ID = re.compile(r'[A-Za-z0-9_-]{16,128}\Z')
STATIC_FILES = frozenset({
    '/', '/index.html', '/script.js', '/style.css',
    '/customer_ui.css', '/customer_ui.js', '/sp_customer_admin_access.js',
})
STATIC_CONTENT_TYPES = {
    'index.html': 'text/html; charset=utf-8',
    'script.js': 'application/javascript; charset=utf-8',
    'style.css': 'text/css; charset=utf-8',
    'customer_ui.css': 'text/css; charset=utf-8',
    'customer_ui.js': 'application/javascript; charset=utf-8',
    'sp_customer_admin_access.js': 'application/javascript; charset=utf-8',
}


def ingress_user(handler):
    """Authorize an HA user only if the trusted Ingress proxy supplied its ID.

    Do not trust a forwarded header from a direct LAN/container caller.  The
    existing HA-admin action layer separately validates Core admin membership.
    """
    try:
        if ipaddress.ip_address(handler.client_address[0]) != INGRESS_PEER:
            return ''
    except (ValueError, IndexError, TypeError):
        return ''
    users = handler.headers.get_all('X-Remote-User-Id', [])
    if len(users) != 1 or not isinstance(users[0], str):
        return ''
    return users[0] if HA_USER_ID.fullmatch(users[0]) else ''


def is_json_browser_post(headers):
    """Cross-origin simple-form POSTs must not mutate local system state."""
    types = headers.get_all('Content-Type', [])
    if len(types) != 1 or types[0].split(';', 1)[0].strip().lower() != 'application/json':
        return False
    sites = headers.get_all('Sec-Fetch-Site', [])
    if len(sites) > 1 or (sites and sites[0] != 'same-origin'):
        return False
    # Requests with no Fetch Metadata must still use non-simple JSON.  CORS
    # preflight is not enabled by this server; other origins cannot issue them.
    return True


class OneShotIntent:
    """Short-lived, user/installation-bound confirmation for Portal disconnect."""
    def __init__(self):
        self._lock = threading.RLock()
        self._proofs = {}

    def issue(self, user, binding, *, now=None):
        if not user or not binding:
            raise ValueError('binding_required')
        now = time.monotonic() if now is None else float(now)
        with self._lock:
            self._proofs = {k: v for k, v in self._proofs.items()
                            if v[2] >= now and v[0] != user}
            token = secrets.token_urlsafe(32)
            self._proofs[token] = (user, binding, now + 120)
            return token

    def consume(self, user, binding, token, *, now=None):
        if not isinstance(token, str) or not 20 <= len(token) <= 100:
            return False
        now = time.monotonic() if now is None else float(now)
        with self._lock:
            saved = self._proofs.pop(token, None)
            return bool(saved and saved[0] == user and saved[1] == binding and saved[2] >= now)


def legacy_subscription_expected(config, *, today=None):
    """Compute the old local expiration without accepting a browser authority bit.

    Preserve JavaScript Date.setMonth rollover behavior for dates such as Jan 31.
    This legacy fallback is not used for Portal-verified service entitlements.
    """
    try:
        raw = str(config.get('sub_start') or '')
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', raw):
            return None
        start = date.fromisoformat(raw)
        months = int(config.get('sub_months', 12))
        if not 1 <= months <= 1200:
            return None
        month_index = (start.year * 12) + start.month - 1 + months
        end_year, month_zero = divmod(month_index, 12)
        if not 1 <= end_year <= 9999:
            return None
        # Using day-1 from month start mimics JS's overflow to next month.
        end_date = date(end_year, month_zero + 1, 1) + timedelta(days=start.day - 1)
        today = date.today() if today is None else today
        return today < end_date
    except (ValueError, OverflowError, TypeError):
        return None


def validate_public_settings_patch(patch, *, now_ms=None):
    """Bound the three historical customer-visible compatibility write keys."""
    allowed = frozenset(('req_history', 'main_history', 'pending_request_time'))
    if not isinstance(patch, dict) or not patch or not set(patch).issubset(allowed):
        return False
    for key in ('req_history', 'main_history'):
        if key not in patch:
            continue
        entries = patch[key]
        if not isinstance(entries, list) or len(entries) > 10:
            return False
        for entry in entries:
            if not isinstance(entry, dict):
                return False
            fields = {'msg', 'time', 'type'} if key == 'req_history' else {'msg', 'time'}
            if not set(entry).issubset(fields) or not isinstance(entry.get('msg'), str) or len(entry['msg']) > 2048:
                return False
            if not isinstance(entry.get('time', ''), str) or len(entry.get('time', '')) > 80:
                return False
            if 'type' in entry and (not isinstance(entry['type'], str) or len(entry['type']) > 64):
                return False
    if 'pending_request_time' in patch:
        n = patch['pending_request_time']
        if type(n) is not int or n < 0:
            return False
        now_ms = int(time.time()*1000) if now_ms is None else int(now_ms)
        if n and not now_ms-24*3600*1000 <= n <= now_ms+60*1000:
            return False
    return True
