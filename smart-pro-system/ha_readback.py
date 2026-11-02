"""Read-only Home Assistant administrator inventory over the Supervisor Core proxy.

SECURITY STATUS: QA 0.2.0, LIVE READ-ONLY TEST, NO USER WRITES.
Reads ``config/auth/list`` from Home Assistant WebSocket. No user writes.
The Supervisor access token is local-only, never returned or logged.

This deliberately uses Python stdlib. It is imported by the isolated QA
add-on only, never by the production Smart Pro System.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
from collections.abc import Mapping
from typing import Any

MAX_HANDSHAKE = 8192
MAX_MESSAGE = 524288
MAX_USERS = 500
DEFAULT_TIMEOUT = 7.0


class AdminReadbackError(RuntimeError):
    """One non-secret failure code (never include an access token)."""


def _read_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise AdminReadbackError("connection_closed")
        data.extend(part)
    return bytes(data)


def _read_frame(sock: socket.socket) -> tuple[int, bytes]:
    start = _read_exact(sock, 2)
    if start[0] & 0x70:
        raise AdminReadbackError("unsupported_frame_extensions")
    if not (start[0] & 0x80):
        # HA normally sends unfragmented JSON. No partial data is accepted.
        raise AdminReadbackError("fragmented_frame_rejected")
    opcode = start[0] & 15
    if start[1] & 128:
        raise AdminReadbackError("server_frame_masked")
    n = start[1] & 127
    if n == 126:
        n = struct.unpack("!H", _read_exact(sock, 2))[0]
    elif n == 127:
        n = struct.unpack("!Q", _read_exact(sock, 8))[0]
    if n > MAX_MESSAGE:
        raise AdminReadbackError("oversized_frame")
    return opcode, _read_exact(sock, n)


def _send_frame(sock: socket.socket, data: bytes, opcode: int = 1) -> None:
    if len(data) > MAX_MESSAGE:
        raise AdminReadbackError("outbound_frame_too_large")
    mask = os.urandom(4)
    first = bytes([0x80 | opcode])
    n = len(data)
    header = bytes([0x80 | n]) if n < 126 else (b"\xfe" + struct.pack("!H", n) if n < 65536 else b"\xff" + struct.pack("!Q", n))
    masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(data))
    sock.sendall(first + header + mask + masked)


def _recv_json(sock: socket.socket) -> dict[str, Any]:
    for _ in range(12):
        opcode, payload = _read_frame(sock)
        if opcode == 9:  # ping -> masked pong
            if len(payload) > 125:
                raise AdminReadbackError("invalid_ping")
            _send_frame(sock, payload, opcode=10)
            continue
        if opcode == 8:
            raise AdminReadbackError("remote_close")
        if opcode != 1:
            raise AdminReadbackError("unexpected_frame_type")
        try:
            message = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AdminReadbackError("invalid_ha_json") from exc
        if not isinstance(message, dict):
            raise AdminReadbackError("invalid_ha_message")
        return message
    raise AdminReadbackError("too_many_control_frames")


def _handshake(sock: socket.socket) -> None:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    expected_accept = base64.b64encode(hashlib.sha1(
        (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
    ).digest()).decode("ascii")
    request = (
        "GET /core/websocket HTTP/1.1\r\n"
        "Host: supervisor\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n\r\n"
    )
    sock.sendall(request.encode("ascii"))
    data = bytearray()
    while b"\r\n\r\n" not in data:
        if len(data) >= MAX_HANDSHAKE:
            raise AdminReadbackError("oversized_upgrade_response")
        fragment = sock.recv(1)  # do not consume first WebSocket frame
        if not fragment:
            raise AdminReadbackError("upgrade_closed")
        data.extend(fragment)
    try:
        header_lines = data.decode("ascii").split("\r\n")
    except UnicodeDecodeError as exc:
        raise AdminReadbackError("invalid_upgrade_response") from exc
    if not header_lines[0].startswith("HTTP/1.1 101 "):
        raise AdminReadbackError("upgrade_rejected")
    headers: dict[str, str] = {}
    for line in header_lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep:
            raise AdminReadbackError("invalid_upgrade_headers")
        name = name.lower().strip()
        if name in headers:
            raise AdminReadbackError("duplicate_upgrade_header")
        headers[name] = value.strip()
    if headers.get("sec-websocket-accept") != expected_accept:
        raise AdminReadbackError("invalid_websocket_accept")
    if headers.get("upgrade", "").lower() != "websocket":
        raise AdminReadbackError("missing_websocket_upgrade")
    if "upgrade" not in [x.strip().lower() for x in headers.get("connection", "").split(",")]:
        raise AdminReadbackError("missing_upgrade_connection")


def _validated_users(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_USERS:
        raise AdminReadbackError("invalid_user_collection")
    seen = set()
    users: list[dict[str, Any]] = []
    for u in raw:
        if not isinstance(u, Mapping):
            raise AdminReadbackError("invalid_user_record")
        uid = u.get("id")
        if not isinstance(uid, str) or not 16 <= len(uid) <= 128 or uid in seen:
            raise AdminReadbackError("invalid_or_duplicate_user_id")
        seen.add(uid)
        if any(type(u.get(field)) is not bool for field in ("is_active", "is_owner", "system_generated")):
            raise AdminReadbackError("incomplete_user_flags")
        groups = u.get("group_ids")
        if not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
            raise AdminReadbackError("invalid_user_groups")
        # discard username, display name and credentials: only authority evidence
        users.append({"id": uid, "is_active": u["is_active"], "is_owner": u["is_owner"],
                      "system_generated": u["system_generated"], "group_ids": groups})
    return users


def read_ha_admin_users(*, supervisor_token: str, timeout: float = DEFAULT_TIMEOUT,
                        connect=socket.create_connection) -> list[dict[str, Any]]:
    """Fetch fresh Core-authenticated user authority evidence; fail closed.

    The real caller MUST source supervisor_token from local environment only.
    The injected socket connector is for isolated test doubles, not Portal input.
    """
    if not isinstance(supervisor_token, str) or len(supervisor_token) < 16:
        raise AdminReadbackError("local_ha_token_unavailable")
    if not (1 <= timeout <= 15):
        raise AdminReadbackError("invalid_timeout")
    try:
        with connect(("supervisor", 80), timeout) as sock:
            sock.settimeout(timeout)
            _handshake(sock)
            challenge = _recv_json(sock)
            if challenge.get("type") != "auth_required":
                raise AdminReadbackError("auth_challenge_missing")
            _send_frame(sock, json.dumps({"type": "auth", "access_token": supervisor_token},
                                         separators=(",", ":")).encode("utf-8"))
            authenticated = _recv_json(sock)
            if authenticated.get("type") != "auth_ok":
                raise AdminReadbackError("ha_auth_failed")
            _send_frame(sock, b'{"id":1,"type":"config/auth/list"}')
            reply = _recv_json(sock)
            if reply.get("id") != 1 or reply.get("type") != "result" or reply.get("success") is not True:
                raise AdminReadbackError("ha_user_list_denied")
            return _validated_users(reply.get("result"))
    except (OSError, TimeoutError) as exc:
        raise AdminReadbackError("ha_connection_failed") from exc
