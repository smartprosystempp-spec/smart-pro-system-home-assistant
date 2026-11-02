"""Only allow-listed Home Assistant Core WebSocket calls for isolated QA.

Used by the retained non-login account lab only. Never expose arbitrary
commands or credentials through the browser or Portal.
"""
from __future__ import annotations
import json
import socket
from collections.abc import Callable
from typing import Any
from ha_readback import AdminReadbackError, _handshake, _recv_json, _send_frame, DEFAULT_TIMEOUT

class RoundTripError(RuntimeError):
    """A constant reason code, never the user's name or secret."""


class SupervisorCoreSession:
    """Single privileged WebSocket, command allow-list, no secrets in logs."""

    ALLOWED = {"config/auth/list", "config/auth/create", "config/auth/delete",
               "config/auth_provider/homeassistant/create"}

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


