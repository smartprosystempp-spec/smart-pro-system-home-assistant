"""QA-only creation + immediate deletion of a non-owner account with NO LOGIN.

WARNING: A created user could remain if Home Assistant crashes after create and
before delete. The static sentinel name prevents subsequent tests if such a user
is still present. Check Settings > People > Users after every live test.

This is NOT customer enrollment, managed technician access, or credential setup.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
from collections.abc import Callable
from typing import Any

from ha_readback import (
    AdminReadbackError,
    _handshake,
    _recv_json,
    _send_frame,
    DEFAULT_TIMEOUT,
)

NAME_PREFIX = "Smart Pro QA TEMP NO LOGIN "
ADMIN_GROUP = "system-admin"


class RoundTripError(RuntimeError):
    """A constant reason code, never the user's name or secret."""


class SupervisorCoreSession:
    """Single privileged WebSocket, command allow-list, no secrets in logs."""

    ALLOWED = {"config/auth/list", "config/auth/create", "config/auth/delete"}

    def __init__(self, supervisor_token: str, timeout: float = DEFAULT_TIMEOUT,
                 connect: Callable = socket.create_connection):
        if not isinstance(supervisor_token, str) or len(supervisor_token) < 16:
            raise RoundTripError("core_auth_unavailable")
        self.token = supervisor_token
        self.timeout = timeout
        self.connect = connect
        self.sock = None
        self.id = 0

    def __enter__(self):
        try:
            self.sock = self.connect(("supervisor", 80), self.timeout)
            self.sock.settimeout(self.timeout)
            _handshake(self.sock)
            if _recv_json(self.sock).get("type") != "auth_required":
                raise RoundTripError("core_challenge_invalid")
            _send_frame(self.sock, json.dumps({"type":"auth", "access_token":self.token},
                                             separators=(",", ":")).encode())
            if _recv_json(self.sock).get("type") != "auth_ok":
                raise RoundTripError("core_auth_denied")
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.token = ""

    def command(self, command_type: str, **params: Any) -> Any:
        if command_type not in self.ALLOWED:
            raise RoundTripError("command_not_allowed")
        self.id += 1
        msg = {"id": self.id, "type": command_type, **params}
        _send_frame(self.sock, json.dumps(msg, separators=(",", ":")).encode())
        result = _recv_json(self.sock)
        if result.get("id") != self.id or result.get("type") != "result":
            raise RoundTripError("core_reply_invalid")
        if result.get("success") is not True:
            raise RoundTripError("core_command_rejected")
        return result.get("result")


def _inventory(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 500:
        raise RoundTripError("inventory_invalid")
    if any(not isinstance(x, dict) or not isinstance(x.get("id"), str)
           or not isinstance(x.get("name"), str) for x in value):
        raise RoundTripError("inventory_invalid")
    return value


def run_qa_roundtrip(*, supervisor_token: str, session_factory=SupervisorCoreSession,
                     suffix_supplier=lambda: secrets.token_hex(6)) -> str:
    """Create admin WITHOUT credentials, verify, delete; return a fixed status.

    The returned result MUST be treated as a lab test; it is not evidence of
    login capability, long-term credential custody or customer approval.
    """
    suffix = suffix_supplier()
    if not isinstance(suffix, str) or len(suffix) != 12 or any(c not in "0123456789abcdef" for c in suffix):
        raise RoundTripError("qa_suffix_invalid")
    name = NAME_PREFIX + suffix
    try:
        with session_factory(supervisor_token) as core:
            users = _inventory(core.command("config/auth/list"))
            if any(str(u.get("name", "")).startswith(NAME_PREFIX) for u in users):
                raise RoundTripError("existing_qa_account_stop")
            created_id = None
            operation_error = None
            cleanup_failed = False
            try:
                result = core.command("config/auth/create", name=name,
                                      group_ids=[ADMIN_GROUP], local_only=True)
                if not isinstance(result, dict) or not isinstance(result.get("user"), dict):
                    raise RoundTripError("create_result_uncertain_check_users")
                user = result["user"]
                uid = user.get("id")
                if not isinstance(uid, str) or not 16 <= len(uid) <= 128:
                    raise RoundTripError("create_id_uncertain_check_users")
                created_id = uid
                current = _inventory(core.command("config/auth/list"))
                matches = [u for u in current if u.get("id") == created_id]
                if len(matches) != 1 or matches[0].get("name") != name:
                    raise RoundTripError("created_user_readback_mismatch")
                item = matches[0]
                if (item.get("is_owner") is not False or item.get("system_generated") is not False
                    or item.get("is_active") is not True or item.get("local_only") is not True
                    or ADMIN_GROUP not in item.get("group_ids", [])):
                    raise RoundTripError("created_user_permissions_mismatch")
                if item.get("credentials"):
                    raise RoundTripError("unexpected_credentials_attached")
            except Exception as exc:
                operation_error = exc
            # Cleanup is attempted even if post-create verification failed.
            if created_id is not None:
                try:
                    core.command("config/auth/delete", user_id=created_id)
                except Exception:
                    cleanup_failed = True
            if cleanup_failed:
                raise RoundTripError("cleanup_uncertain_check_users")
            if operation_error is not None:
                raise operation_error
            after = _inventory(core.command("config/auth/list"))
            if any(u.get("id") == created_id or str(u.get("name", "")).startswith(NAME_PREFIX) for u in after):
                raise RoundTripError("cleanup_not_confirmed_check_users")
            return "qa_account_created_verified_deleted"
    except RoundTripError:
        raise
    except (AdminReadbackError, OSError, TimeoutError, ValueError, TypeError):
        raise RoundTripError("core_roundtrip_failed_check_users") from None
