#!/usr/bin/env python3
"""Smart Pro Tunnel 0.1.6 — private Home Assistant TCP proxy + enrollment-material bridge.

Security boundary:
- dedicated WireGuard identity stored only in this app's persistent /data volume;
- outbound-only connection to the Smart Pro External Gateway;
- no host network, no host port mapping, no IP forwarding/NAT;
- optional private TCP proxy binds only to the WireGuard /32 and forwards to Home Assistant;
- no public URL/DNS/public ingress in this milestone;
- a tiny HTTP health endpoint binds only to the WireGuard /32 address.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP_VERSION = os.environ.get("APP_VERSION", "0.0.0")
OPTIONS_FILE = Path("/data/options.json")
STATE_DIR = Path("/data/wireguard")
PRIVATE_KEY_FILE = STATE_DIR / "private.key"
PUBLIC_KEY_FILE = STATE_DIR / "public.key"
STATUS_FILE = STATE_DIR / "status.json"

INTERFACE = "wg0"
GATEWAY_ALLOWED_IP = "10.203.0.1/32"
TUNNEL_NETWORK = ipaddress.ip_network("10.203.0.0/16")
RESERVED_NETWORK = ipaddress.ip_network("10.203.0.0/24")
HEALTH_PORT = 8788
MTU = 1380
PERSISTENT_KEEPALIVE = 25
DEFAULT_HA_TARGET_HOST = "172.30.32.1"
DEFAULT_HA_TARGET_PORT = 8123
HA_PROBE_TIMEOUT = 3
PRIVATE_PROXY_PORT = 18123
GATEWAY_TUNNEL_IP = "10.203.0.1"
PROXY_CONNECT_TIMEOUT = 5
ENROLLMENT_CONTRACT = "smart-pro-tunnel-enrollment-material-v1"
ENROLLMENT_DIR = Path("/share/smart-pro/tunnel")
ENROLLMENT_FILE = ENROLLMENT_DIR / "enrollment.json"
SHARED_RUNTIME_STATUS_FILE = ENROLLMENT_DIR / "runtime-status.json"

STOP_EVENT = threading.Event()
STATUS_LOCK = threading.RLock()
CURRENT_STATUS: dict[str, object] = {}
USERSPACE_PROCESS: subprocess.Popen[str] | None = None
HTTP_SERVER: ThreadingHTTPServer | None = None
PROXY_SERVER_SOCKET: socket.socket | None = None
PROXY_THREAD: threading.Thread | None = None
ACTIVE_PROXY_CONNECTIONS: set[socket.socket] = set()
PROXY_CONNECTIONS_LOCK = threading.Lock()


def log(message: str) -> None:
    print(f"[TUNNEL] {message}", flush=True)


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    os.chmod(path, mode)


def atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    atomic_write_text(
        path,
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        0o600,
    )


def publish_enrollment_material(public_key: str) -> bool:
    """Publish public-only WireGuard enrollment material for Smart Pro Tools.

    This deliberately contains no private key, Portal credential, Gateway secret or
    runtime write authority. Failure to publish must not break an already-working
    tunnel; it only leaves future automated provisioning preflight unavailable.
    """
    try:
        validate_public_key(public_key)
        ENROLLMENT_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(ENROLLMENT_DIR, 0o700)
        payload = {
            "contract": ENROLLMENT_CONTRACT,
            "version": APP_VERSION,
            "public_key": public_key,
            "source": "smart_pro_tunnel_local_share",
            "private_key_exposed": False,
            "runtime_authority": False,
            "updated_at": int(time.time()),
        }
        atomic_write_json(ENROLLMENT_FILE, payload)
        os.chmod(ENROLLMENT_FILE, 0o600)
        return True
    except Exception as exc:
        log(f"Enrollment material publication unavailable: {type(exc).__name__}")
        return False


def run(command: list[str], *, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        check=check,
    )


def load_options() -> dict[str, object]:
    try:
        raw = json.loads(OPTIONS_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"options_unavailable:{type(exc).__name__}") from exc
    if not isinstance(raw, dict):
        raise RuntimeError("options_invalid")
    return raw


def validate_gateway_endpoint(value: object) -> str:
    endpoint = str(value or "").strip()
    match = re.fullmatch(r"([A-Za-z0-9.-]+):([0-9]{1,5})", endpoint)
    if not match:
        raise ValueError("gateway_endpoint_invalid")
    host, port_raw = match.groups()
    if host.startswith(".") or host.endswith(".") or ".." in host:
        raise ValueError("gateway_endpoint_invalid")
    port = int(port_raw)
    if port < 1 or port > 65535:
        raise ValueError("gateway_endpoint_invalid")
    return f"{host}:{port}"


def validate_public_key(value: object) -> str:
    key = str(value or "").strip()
    try:
        decoded = base64.b64decode(key.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError("gateway_public_key_invalid") from exc
    if len(decoded) != 32:
        raise ValueError("gateway_public_key_invalid")
    return key


def validate_peer_address(value: object) -> str:
    raw = str(value or "").strip()
    try:
        interface = ipaddress.ip_interface(raw)
    except ValueError as exc:
        raise ValueError("peer_address_invalid") from exc
    if interface.version != 4 or interface.network.prefixlen != 32:
        raise ValueError("peer_address_must_be_ipv4_32")
    if interface.ip not in TUNNEL_NETWORK:
        raise ValueError("peer_address_outside_smart_pro_tunnel_network")
    if interface.ip in RESERVED_NETWORK:
        raise ValueError("peer_address_in_reserved_gateway_range")
    return f"{interface.ip}/32"


def validate_home_assistant_target_host(value: object) -> str:
    raw = str(value or "").strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ValueError("home_assistant_target_host_invalid") from exc
    if address.version != 4 or not address.is_private or address.is_loopback or address.is_multicast or address.is_unspecified:
        raise ValueError("home_assistant_target_host_invalid")
    return str(address)


def validate_home_assistant_target_port(value: object) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("home_assistant_target_port_invalid") from exc
    if port < 1 or port > 65535:
        raise ValueError("home_assistant_target_port_invalid")
    return port


def ensure_wireguard_identity() -> str:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)

    if not PRIVATE_KEY_FILE.exists():
        result = run(["wg", "genkey"])
        private_key = result.stdout.strip()
        if not private_key:
            raise RuntimeError("wireguard_private_key_generation_failed")
        atomic_write_text(PRIVATE_KEY_FILE, private_key + "\n", 0o600)
        log("Created persistent WireGuard identity in /data (private key not printed).")
    else:
        os.chmod(PRIVATE_KEY_FILE, 0o600)

    private_key = PRIVATE_KEY_FILE.read_text(encoding="utf-8").strip()
    public = run(["wg", "pubkey"], input_text=private_key + "\n").stdout.strip()
    validate_public_key(public)
    atomic_write_text(PUBLIC_KEY_FILE, public + "\n", 0o644)
    return public


def safe_status_base(public_key: str, peer_address: str, enabled: bool, target_host: str, target_port: int, target_ssl: bool) -> dict[str, object]:
    return {
        "contract": "smart-pro-private-tunnel-canary-v1",
        "version": APP_VERSION,
        "enabled": bool(enabled),
        "interface": INTERFACE,
        "peer_address": peer_address,
        "public_key": public_key,
        "gateway_allowed_ip": GATEWAY_ALLOWED_IP,
        "health_port": HEALTH_PORT,
        "ip_forwarding": False,
        "nat": False,
        "host_network": False,
        "home_assistant_proxy": False,
        "private_proxy_enabled": False,
        "private_proxy_port": PRIVATE_PROXY_PORT,
        "private_proxy_state": "off",
        "home_assistant_target": f"{target_host}:{target_port}",
        "home_assistant_target_ssl": bool(target_ssl),
        "home_assistant_target_probe": "pending",
        "home_assistant_target_reachable": False,
        "home_assistant_target_http_status": None,
        "public_url": False,
        "dns_published": False,
        "private_key_exposed": False,
        "updated_at": int(time.time()),
    }


def publish_shared_runtime_status(payload: dict[str, object]) -> None:
    try:
        public_key=str(payload.get('public_key','') or '')
        safe={
            'contract':'smart-pro-tunnel-runtime-status-v1','version':APP_VERSION,'enabled':bool(payload.get('enabled',False)),
            'state':str(payload.get('state','off') or 'off')[:32],'peer_address':str(payload.get('peer_address','') or '')[:64],
            'public_key_sha256':__import__('hashlib').sha256(public_key.encode('utf-8')).hexdigest() if public_key else '',
            'private_proxy_enabled':bool(payload.get('private_proxy_enabled',False)),'private_proxy_state':str(payload.get('private_proxy_state','off') or 'off')[:32],
            'home_assistant_target_reachable':bool(payload.get('home_assistant_target_reachable',False)),
            'handshake_age_seconds':payload.get('handshake_age_seconds'), 'updated_at':int(time.time()),
            'private_key_exposed':False,'public_url':False,'dns_published':False,
        }
        ENROLLMENT_DIR.mkdir(parents=True,exist_ok=True); os.chmod(ENROLLMENT_DIR,0o700); atomic_write_json(SHARED_RUNTIME_STATUS_FILE,safe); os.chmod(SHARED_RUNTIME_STATUS_FILE,0o600)
    except Exception as exc:
        log(f"Shared runtime status unavailable: {type(exc).__name__}")

def publish_status(payload: dict[str, object]) -> None:
    global CURRENT_STATUS
    payload = dict(payload)
    payload["updated_at"] = int(time.time())
    with STATUS_LOCK:
        CURRENT_STATUS = payload
        atomic_write_json(STATUS_FILE, payload)
    publish_shared_runtime_status(payload)


def create_interface() -> str:
    global USERSPACE_PROCESS

    kernel_try = run(["ip", "link", "add", "dev", INTERFACE, "type", "wireguard"], check=False)
    if kernel_try.returncode == 0:
        return "kernel"

    log("Kernel WireGuard interface unavailable in the app namespace; using wireguard-go userspace fallback.")
    USERSPACE_PROCESS = subprocess.Popen(
        ["wireguard-go", INTERFACE],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    deadline = time.time() + 10
    while time.time() < deadline:
        probe = run(["ip", "link", "show", "dev", INTERFACE], check=False)
        if probe.returncode == 0:
            return "userspace"
        if USERSPACE_PROCESS.poll() is not None:
            output = USERSPACE_PROCESS.stdout.read() if USERSPACE_PROCESS.stdout else ""
            raise RuntimeError(f"wireguard_go_failed:{output.strip()[:200]}")
        time.sleep(0.2)

    raise RuntimeError("wireguard_interface_timeout")


def configure_interface(peer_address: str, gateway_public_key: str, gateway_endpoint: str) -> None:
    run(["ip", "address", "add", peer_address, "dev", INTERFACE])
    run(
        [
            "wg", "set", INTERFACE,
            "private-key", str(PRIVATE_KEY_FILE),
            "peer", gateway_public_key,
            "endpoint", gateway_endpoint,
            "allowed-ips", GATEWAY_ALLOWED_IP,
            "persistent-keepalive", str(PERSISTENT_KEEPALIVE),
        ]
    )
    run(["ip", "link", "set", "dev", INTERFACE, "mtu", str(MTU), "up"])
    run(["ip", "route", "replace", GATEWAY_ALLOWED_IP, "dev", INTERFACE])



def probe_home_assistant_target(target_host: str, target_port: int) -> dict[str, object]:
    """Read-only TCP reachability probe for the exact Supervisor-discovered Core target.

    The private proxy is a raw TCP forwarder, so readiness must not assume HTTP
    plaintext. This remains valid when Home Assistant Core itself is configured
    with SSL/TLS. No Home Assistant token or API permission is used.
    """
    result: dict[str, object] = {
        "home_assistant_target_probe": "unreachable",
        "home_assistant_target_reachable": False,
        "home_assistant_target_http_status": None,
    }
    try:
        with socket.create_connection((target_host, target_port), timeout=HA_PROBE_TIMEOUT):
            pass
        result["home_assistant_target_probe"] = "tcp_ready"
        result["home_assistant_target_reachable"] = True
        return result
    except socket.gaierror:
        result["home_assistant_target_probe"] = "dns_unavailable"
        return result
    except (TimeoutError, socket.timeout):
        result["home_assistant_target_probe"] = "timeout"
        return result
    except OSError:
        result["home_assistant_target_probe"] = "connection_failed"
        return result


def relay_stream(source: socket.socket, destination: socket.socket) -> None:
    try:
        while not STOP_EVENT.is_set():
            data = source.recv(65536)
            if not data:
                break
            destination.sendall(data)
    except (OSError, TimeoutError):
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle_proxy_client(client: socket.socket, address: tuple[str, int], target_host: str, target_port: int) -> None:
    upstream: socket.socket | None = None
    try:
        client_ip = str(address[0])
        if client_ip != GATEWAY_TUNNEL_IP:
            log(f"Private proxy rejected unexpected tunnel source {client_ip}.")
            return

        upstream = socket.create_connection(
            (target_host, target_port),
            timeout=PROXY_CONNECT_TIMEOUT,
        )
        client.settimeout(None)
        upstream.settimeout(None)

        t1 = threading.Thread(target=relay_stream, args=(client, upstream), daemon=True)
        t2 = threading.Thread(target=relay_stream, args=(upstream, client), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except OSError:
        pass
    finally:
        for sock in (upstream, client):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        with PROXY_CONNECTIONS_LOCK:
            ACTIVE_PROXY_CONNECTIONS.discard(client)
            if upstream is not None:
                ACTIVE_PROXY_CONNECTIONS.discard(upstream)


def proxy_accept_loop(bind_ip: str, target_host: str, target_port: int) -> None:
    global PROXY_SERVER_SOCKET

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_ip, PRIVATE_PROXY_PORT))
    server.listen(16)
    server.settimeout(1.0)
    PROXY_SERVER_SOCKET = server

    while not STOP_EVENT.is_set():
        try:
            client, address = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        with PROXY_CONNECTIONS_LOCK:
            ACTIVE_PROXY_CONNECTIONS.add(client)

        threading.Thread(
            target=handle_proxy_client,
            args=(client, address, target_host, target_port),
            name="private-ha-proxy-client",
            daemon=True,
        ).start()


def start_private_proxy(bind_ip: str, target_host: str, target_port: int) -> threading.Thread:
    thread = threading.Thread(
        target=proxy_accept_loop,
        args=(bind_ip, target_host, target_port),
        name="private-ha-proxy",
        daemon=True,
    )
    thread.start()

    deadline = time.time() + 5
    while time.time() < deadline:
        server = PROXY_SERVER_SOCKET
        if server is not None:
            return thread
        if not thread.is_alive():
            break
        time.sleep(0.05)

    raise RuntimeError("private_proxy_start_failed")

def parse_peer_metric(command: str) -> int:
    result = run(["wg", "show", INTERFACE, command], check=False)
    if result.returncode != 0:
        return 0
    line = result.stdout.strip().splitlines()
    if not line:
        return 0
    fields = line[0].split()
    if len(fields) < 2:
        return 0
    try:
        return max(0, int(fields[1]))
    except ValueError:
        return 0


def transfer_metrics() -> tuple[int, int]:
    result = run(["wg", "show", INTERFACE, "transfer"], check=False)
    if result.returncode != 0:
        return 0, 0
    lines = result.stdout.strip().splitlines()
    if not lines:
        return 0, 0
    fields = lines[0].split()
    if len(fields) < 3:
        return 0, 0
    try:
        return max(0, int(fields[1])), max(0, int(fields[2]))
    except ValueError:
        return 0, 0


def refreshed_runtime_status(base: dict[str, object], transport: str, target_host: str, target_port: int) -> dict[str, object]:
    now = int(time.time())
    latest = parse_peer_metric("latest-handshakes")
    rx_bytes, tx_bytes = transfer_metrics()
    handshake_age = max(0, now - latest) if latest > 0 else None

    if latest <= 0:
        state = "up_no_handshake"
    elif handshake_age is not None and handshake_age <= 180:
        state = "connected"
    else:
        state = "handshake_stale"

    status = dict(base)
    status.update(probe_home_assistant_target(target_host, target_port))
    status.update(
        {
            "state": state,
            "transport": transport,
            "latest_handshake_at": latest,
            "handshake_age_seconds": handshake_age,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
        }
    )
    return status


class HealthHandler(BaseHTTPRequestHandler):
    server_version = "SmartProTunnel/0.1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self.send_response(404)
            self.end_headers()
            return
        with STATUS_LOCK:
            payload = dict(CURRENT_STATUS)
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def cleanup() -> None:
    global HTTP_SERVER, USERSPACE_PROCESS, PROXY_SERVER_SOCKET, PROXY_THREAD

    if PROXY_SERVER_SOCKET is not None:
        try:
            PROXY_SERVER_SOCKET.close()
        except Exception:
            pass
        PROXY_SERVER_SOCKET = None

    with PROXY_CONNECTIONS_LOCK:
        sockets = list(ACTIVE_PROXY_CONNECTIONS)
        ACTIVE_PROXY_CONNECTIONS.clear()
    for sock in sockets:
        try:
            sock.close()
        except OSError:
            pass

    PROXY_THREAD = None

    if HTTP_SERVER is not None:
        try:
            HTTP_SERVER.shutdown()
            HTTP_SERVER.server_close()
        except Exception:
            pass
        HTTP_SERVER = None

    run(["ip", "link", "del", "dev", INTERFACE], check=False)

    if USERSPACE_PROCESS is not None and USERSPACE_PROCESS.poll() is None:
        USERSPACE_PROCESS.terminate()
        try:
            USERSPACE_PROCESS.wait(timeout=3)
        except subprocess.TimeoutExpired:
            USERSPACE_PROCESS.kill()
        USERSPACE_PROCESS = None


def signal_handler(_signum: int, _frame: object) -> None:
    STOP_EVENT.set()


def main() -> int:
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    options = load_options()
    enabled = bool(options.get("enabled", False))
    private_proxy_enabled = bool(options.get("private_proxy_enabled", False))
    peer_address = validate_peer_address(options.get("peer_address", "10.203.1.1/32"))
    target_host = validate_home_assistant_target_host(options.get("home_assistant_target_host", DEFAULT_HA_TARGET_HOST))
    target_port = validate_home_assistant_target_port(options.get("home_assistant_target_port", DEFAULT_HA_TARGET_PORT))
    target_ssl = bool(options.get("home_assistant_target_ssl", False))
    public_key = ensure_wireguard_identity()
    enrollment_published = publish_enrollment_material(public_key)

    base = safe_status_base(public_key, peer_address, enabled, target_host, target_port, target_ssl)
    base["enrollment_material_published"] = enrollment_published
    base["private_proxy_enabled"] = private_proxy_enabled
    base["state"] = "identity_ready"
    publish_status(base)

    log(f"Peer public key: {public_key}")
    log(f"Peer tunnel address: {peer_address}")
    log(f"Home Assistant private target: {target_host}:{target_port}; ssl={str(target_ssl).lower()}")

    if not enabled:
        log("Runtime is DISABLED. Identity is ready; no tunnel interface or network route was created.")
        while not STOP_EVENT.wait(30):
            publish_status(base | {"state": "identity_ready"})
        return 0

    gateway_endpoint = validate_gateway_endpoint(options.get("gateway_endpoint"))
    gateway_public_key = validate_public_key(options.get("gateway_public_key"))

    transport = create_interface()
    try:
        configure_interface(peer_address, gateway_public_key, gateway_endpoint)
        base.update(
            {
                "gateway_endpoint_configured": True,
                "gateway_public_key_configured": True,
            }
        )
        status = refreshed_runtime_status(base, transport, target_host, target_port)
        publish_status(status)

        bind_ip = peer_address.split("/", 1)[0]
        global HTTP_SERVER
        HTTP_SERVER = ThreadingHTTPServer((bind_ip, HEALTH_PORT), HealthHandler)
        server_thread = threading.Thread(target=HTTP_SERVER.serve_forever, name="tunnel-health", daemon=True)
        server_thread.start()

        log(f"Interface {INTERFACE} UP via {transport}; allowed route is only {GATEWAY_ALLOWED_IP}.")
        log(f"Private health endpoint is listening only on {bind_ip}:{HEALTH_PORT}/health over the tunnel.")
        initial_probe = probe_home_assistant_target(target_host, target_port)
        publish_status(refreshed_runtime_status(base | initial_probe, transport, target_host, target_port))
        log(
            "Home Assistant target probe: "
            f"{initial_probe.get('home_assistant_target_probe')}"
            f"; http_status={initial_probe.get('home_assistant_target_http_status')}"
        )

        if private_proxy_enabled:
            if not bool(initial_probe.get("home_assistant_target_reachable", False)):
                raise RuntimeError("private_proxy_target_not_ready")
            global PROXY_THREAD
            PROXY_THREAD = start_private_proxy(bind_ip, target_host, target_port)
            base.update(
                {
                    "home_assistant_proxy": True,
                    "private_proxy_state": "listening",
                }
            )
            publish_status(refreshed_runtime_status(base | initial_probe, transport, target_host, target_port))
            log(
                f"Private Home Assistant TCP proxy is listening only on "
                f"{bind_ip}:{PRIVATE_PROXY_PORT} and forwards to {target_host}:{target_port}."
            )
            log(f"Private proxy accepts only gateway tunnel source {GATEWAY_TUNNEL_IP}.")
        else:
            log("Private Home Assistant proxy is DISABLED.")

        log("No public URL, DNS publication, NAT or IP forwarding is enabled.")

        last_state = None
        while not STOP_EVENT.wait(10):
            status = refreshed_runtime_status(base, transport, target_host, target_port)
            publish_status(status)
            state = str(status.get("state", ""))
            if state != last_state:
                age = status.get("handshake_age_seconds")
                age_text = "none" if age is None else str(age)
                log(f"State: {state}; handshake_age_seconds={age_text}")
                last_state = state

        return 0
    finally:
        cleanup()
        publish_status(base | {"state": "stopped"})
        log("Stopped cleanly.")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        try:
            options = load_options()
            peer_address = validate_peer_address(options.get("peer_address", "10.203.1.1/32"))
            public_key = PUBLIC_KEY_FILE.read_text(encoding="utf-8").strip() if PUBLIC_KEY_FILE.exists() else ""
            target_host = validate_home_assistant_target_host(options.get("home_assistant_target_host", DEFAULT_HA_TARGET_HOST))
            target_port = validate_home_assistant_target_port(options.get("home_assistant_target_port", DEFAULT_HA_TARGET_PORT))
            target_ssl = bool(options.get("home_assistant_target_ssl", False))
            failure = safe_status_base(public_key, peer_address, bool(options.get("enabled", False)), target_host, target_port, target_ssl)
            failure["private_proxy_enabled"] = bool(options.get("private_proxy_enabled", False))
            failure.update({"state": "failed", "reason": str(exc)[:160]})
            publish_status(failure)
        except Exception:
            pass
        log(f"FAILED: {type(exc).__name__}: {str(exc)[:160]}")
        cleanup()
        raise
