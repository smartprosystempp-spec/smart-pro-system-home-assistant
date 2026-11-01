#!/usr/bin/env python3
"""Smart Pro customer administrator preflight, strictly read-only.

This disposable QA app has no Home Assistant or Supervisor API token, no
account/user write code, and no stateful storage. It must only be opened via
Home Assistant Supervisor Ingress. Do not reuse this preflight as consent to
provision an account: a new consent flow and its own reviewed gate are needed.
"""

from __future__ import annotations

import html
import ipaddress
import json
import os
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping
from urllib.parse import urlsplit

from ha_readback import AdminReadbackError, read_ha_admin_users

APP_VERSION = "0.2.0"
PORT = 8107
SUPERVISOR_INGRESS_PEER = ipaddress.ip_address("172.30.32.2")
USER_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
ADMIN_GROUP = "system-admin"
MAX_GROUPS_HEADER = 1024


def verify_ingress_admin(peer_ip: str, headers: Mapping[str, str]) -> dict[str, str | bool]:
    """Verify trusted Supervisor ingress role headers, without state or writes.

    Security assumptions: the host port is NOT published; the app checks the
    kernel-observed socket peer, never X-Forwarded-For. The Supervisor removes
    client-supplied X-Remote-User-{Id,Groups} and supplies its own values.
    No role data from browser form, URL, JSON body or query string is trusted.
    """
    deny = lambda reason: {"is_admin": False, "reason": reason}
    try:
        peer = ipaddress.ip_address(peer_ip)
    except ValueError:
        return deny("untrusted_source")
    if peer != SUPERVISOR_INGRESS_PEER:
        return deny("untrusted_source")

    lowered = {str(key).lower(): value for key, value in headers.items()}
    user_id = lowered.get("x-remote-user-id", "")
    group_header = lowered.get("x-remote-user-groups", "")
    if not isinstance(user_id, str) or USER_ID_PATTERN.fullmatch(user_id) is None:
        return deny("identity_unavailable")
    if not isinstance(group_header, str) or len(group_header) > MAX_GROUPS_HEADER:
        return deny("groups_unavailable")
    if not group_header or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-," for char in group_header):
        return deny("groups_unavailable")
    groups = group_header.split(",")
    if any(not group for group in groups) or len(groups) > 40:
        return deny("groups_unavailable")
    if ADMIN_GROUP not in groups:
        return deny("non_admin")

    # This is preflight eligibility only. It never grants or records approval.
    return {"is_admin": True, "reason": "admin_detected"}



def verify_live_core_admin(peer_ip: str, headers: Mapping[str, str], *,
                           token_supplier=None, user_reader=read_ha_admin_users) -> dict[str, str | bool]:
    """Check trust *twice*: Supervisor ingress and fresh HA Core admin list.

    The Core list is used only in RAM and never returned or logged. This is
    neither approval nor provisioning. Normal users fail *before* the privileged
    token is accessed. The token supplier is injectable solely for offline QA.
    """
    baseline = verify_ingress_admin(peer_ip, headers)
    if baseline["is_admin"] is not True:
        return baseline

    identity_values = [v for k, v in headers.items() if str(k).lower() == "x-remote-user-id"]
    if len(identity_values) != 1:
        return {"is_admin": False, "reason": "identity_unavailable"}
    user_id = identity_values[0]
    if not isinstance(user_id, str) or USER_ID_PATTERN.fullmatch(user_id) is None:
        return {"is_admin": False, "reason": "identity_unavailable"}
    if token_supplier is None:
        token_supplier = lambda: os.environ.get("SUPERVISOR_TOKEN", "")
    try:
        token = token_supplier()
        users = user_reader(supervisor_token=token)
    except AdminReadbackError as exc:
        # Fixed opaque failure codes. No username, user IDs or token ever leaked.
        if str(exc) in ("ha_user_list_denied", "ha_auth_failed", "local_ha_token_unavailable"):
            return {"is_admin": False, "reason": "core_authority_denied"}
        return {"is_admin": False, "reason": "core_readback_failed"}
    except Exception:
        return {"is_admin": False, "reason": "core_readback_failed"}

    if not isinstance(users, list):
        return {"is_admin": False, "reason": "core_invalid_reply"}
    matches = [u for u in users if isinstance(u, dict) and u.get("id") == user_id]
    if len(matches) != 1:
        return {"is_admin": False, "reason": "core_identity_not_matched"}
    u = matches[0]
    groups = u.get("group_ids")
    if (u.get("is_active") is not True or u.get("system_generated") is not False
            or not isinstance(groups, list)
            or not all(isinstance(g, str) for g in groups)
            or (u.get("is_owner") is not True and ADMIN_GROUP not in groups)):
        return {"is_admin": False, "reason": "core_user_not_admin"}
    return {"is_admin": True, "reason": "admin_and_core_verified_read_only"}


def render_page(outcome: dict[str, str | bool]) -> bytes:
    ok = outcome["is_admin"] is True
    if ok:
        title = "Διαχειριστής Home Assistant — επιβεβαιώθηκε και από το Core"
        description = (
            "Το Home Assistant αναγνώρισε τον διαχειριστή και επέτρεψε την ασφαλή ανάγνωση "
            "των δικαιωμάτων χρηστών μέσω Core API. Κανένας χρήστης δεν δημιουργήθηκε ή τροποποιήθηκε."
        )
        badge_class = "ok"
    else:
        title = "Δεν επιβεβαιώθηκε διαχειριστής"
        if outcome["reason"] == "non_admin":
            description = "Ο τρέχων λογαριασμός δεν έχει δικαιώματα διαχειριστή."
        elif outcome["reason"] == "untrusted_source":
            description = "Ανοίξτε αυτό το εργαλείο μόνο από το Home Assistant."
        elif str(outcome["reason"]).startswith("core_"):
            description = (
                "Η αρχική ταυτότητα ήταν διαχειριστή, αλλά δεν επιβεβαιώθηκε η πρόσβαση "
                "στο προστατευμένο Core API. Δεν πραγματοποιήθηκε καμία αλλαγή. "
                "Κωδικός ελέγχου: " + str(outcome["reason"])
            )
        else:
            description = "Το Home Assistant δεν επέστρεψε επαρκή στοιχεία για ασφαλή επιβεβαίωση."
        badge_class = "blocked"
    return f"""<!doctype html>
<html lang="el"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Smart Pro Access — QA</title>
<style>
:root{{color-scheme:light dark}}*{{box-sizing:border-box}}body{{margin:0;background:#101722;color:#e9eef7;font:16px/1.55 system-ui,-apple-system,sans-serif}}
main{{max-width:610px;margin:8vh auto;padding:26px;border:1px solid #354254;border-radius:16px;background:#172232}}
h1{{font-size:1.42rem;line-height:1.35;margin:.5rem 0 1rem}}.k{{font-weight:700;letter-spacing:.05em;color:#b6c6da;font-size:.78rem}}
.status{{display:inline-block;border-radius:100px;padding:5px 11px;font-size:.82rem;font-weight:700}}.ok{{background:#173d32;color:#a8f1c5}}.blocked{{background:#50302d;color:#ffcbc3}}
p{{color:#c7d2e1}}.note{{font-size:.88rem;padding-top:15px;border-top:1px solid #354254}}
</style></head><body><main><div class="k">SMART PRO SYSTEM · ΔΟΚΙΜΑΣΤΙΚΟΣ ΕΛΕΓΧΟΣ</div>
<h1>{html.escape(title)}</h1><span class="status {badge_class}">{'ΕΠΙΤΥΧΙΑ' if ok else 'ΔΕΝ ΕΓΚΡΙΝΕΤΑΙ'}</span>
<p>{html.escape(description)}</p><p class="note">Πρόκειται μόνο για δοκιμή ταυτότητας και ανάγνωσης δικαιωμάτων του Core. Δεν μεταφέρονται κωδικοί.
Δεν συνδέεται με το Portal, δεν προσθέτει χρήστες και δεν αλλάζει το Managed Support.</p>
<p class="note">Έκδοση QA {APP_VERSION} · Για επανέλεγχο ανανεώστε τη σελίδα.</p></main></body></html>""".encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "SmartProQA"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        # Never log query parameters, user IDs or identity headers.
        return

    def _write(self, status: int, data: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, private, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path not in ("/", "/status"):
            self._write(HTTPStatus.NOT_FOUND, b"Not found", "text/plain")
            return
        outcome = verify_live_core_admin(self.client_address[0], self.headers)
        status = HTTPStatus.OK if outcome["is_admin"] else HTTPStatus.FORBIDDEN
        if path == "/status":
            # Status contains only boolean and fixed reason, no user identifiers.
            body = json.dumps({"version": APP_VERSION, **outcome}, separators=(",", ":")).encode()
            self._write(status, body, "application/json; charset=utf-8")
        else:
            self._write(status, render_page(outcome), "text/html; charset=utf-8")

    def do_POST(self) -> None:
        self._write(HTTPStatus.METHOD_NOT_ALLOWED, b"Read-only QA", "text/plain")

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    # Deliberately no host port publication; Supervisor ingress is the sole path.
    with Server(("0.0.0.0", PORT), Handler) as server:
        print(f"[smart-pro-access-qa] {APP_VERSION} ready; read-only Core admin proof; ingress-only", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
