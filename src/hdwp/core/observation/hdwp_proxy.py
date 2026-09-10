# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file in the root.

"""
HDWPProxy: proxy MITM HTTP/HTTPS natif basé sur asyncio + cryptography.
Remplace mitmproxy sans dépendance externe.

Limitations connues :
- HTTP/2 non supporté (forcé en HTTP/1.1 via ALPN)
- Nécessite Python >= 3.11 pour loop.start_tls()
"""
from __future__ import annotations

import asyncio
import datetime
import ipaddress
import json
import re
import ssl
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import structlog

from hdwp.core.bus.events import CREDENTIALS_CAPTURED, OBSERVATION_RAW
from hdwp.core.model.schemas import ObservationType, RawObservation
from hdwp.core.observation.normalizer import normalize_request, normalize_response

if TYPE_CHECKING:
    from hdwp.core.bus.event_bus import AsyncEventBus
    from hdwp.core.context.scope_guard import ScopeGuard

log = structlog.get_logger()

# ── Paths ─────────────────────────────────────────────────────────────────────
HDWP_HOME = Path.home() / ".hdwp"
CA_CERT_PATH = HDWP_HOME / "ca.crt"
CA_KEY_PATH  = HDWP_HOME / "ca.key"
CERTS_DIR    = HDWP_HOME / "certs"

# ── Auth token extraction ──────────────────────────────────────────────────────

_BEARER_RE = re.compile(r"bearer\s+([A-Za-z0-9\-_.~+/]+=*)", re.IGNORECASE)
_JWT_RE     = re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.]+")


def _extract_auth_token(
    body_json: dict | None,
    headers: dict[str, str],
) -> tuple[str, str] | None:
    """Return (token_type, token_value) or None."""
    auth = headers.get("authorization", headers.get("Authorization", ""))
    if auth:
        m = _BEARER_RE.search(auth)
        if m:
            return ("bearer", m.group(1))
    if body_json and isinstance(body_json, dict):
        for key in ("access_token", "token", "jwt", "id_token", "accessToken"):
            val = body_json.get(key, "")
            if isinstance(val, str) and _JWT_RE.match(val):
                return ("bearer", val)
    cookie_hdr = headers.get("set-cookie", "")
    if cookie_hdr:
        for part in cookie_hdr.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                if k.lower() in ("session", "sessionid", "sid", "auth_token", "token"):
                    return ("cookie", f"{k}={v}")
    return None


# ── CA and certificate generation ─────────────────────────────────────────────

def _load_or_create_ca():  # type: ignore[return]
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        log.error("hdwp_proxy.cryptography_missing")
        raise RuntimeError("cryptography package required: pip install cryptography")

    HDWP_HOME.mkdir(parents=True, exist_ok=True)
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    if CA_CERT_PATH.exists() and CA_KEY_PATH.exists():
        try:
            ca_cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
            ca_key = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
            return ca_cert, ca_key
        except Exception:
            pass

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "HDWP Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HDWP Pentest Engine"),
    ])
    now = datetime.datetime.now(datetime.UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    CA_CERT_PATH.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    CA_KEY_PATH.write_bytes(ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    CA_KEY_PATH.chmod(0o600)
    log.info("hdwp_proxy.ca_created", path=str(CA_CERT_PATH))
    return ca_cert, ca_key


def _gen_cert_for_host(hostname: str, ca_cert: object, ca_key: object) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", hostname)
    cert_path = CERTS_DIR / f"{safe_name}.crt"
    key_path  = CERTS_DIR / f"{safe_name}.key"

    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    try:
        san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(hostname))
    except ValueError:
        san = x509.DNSName(hostname)

    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_cert.subject)  # type: ignore[attr-defined]
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .sign(ca_key, hashes.SHA256())  # type: ignore[arg-type]
    )

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    return cert_path, key_path


# ── JS error collector injection ─────────────────────────────────────────────

_JS_COLLECTOR_SNIPPET = b"""<script>
(function(){var _e=[];
  var _orig=console.error;console.error=function(){_e.push({t:'e',m:[].join.call(arguments,' ')});_orig.apply(this,arguments);};
  window.onerror=function(m,s,l){_e.push({t:'ex',m:m,src:s,line:l});return false;};
  window.addEventListener('unhandledrejection',function(ev){_e.push({t:'rej',m:String(ev.reason)});});
  setInterval(function(){if(_e.length){try{navigator.sendBeacon('/__hdwp_console__',JSON.stringify(_e.splice(0)));}catch(e){};}},2000);
})();
</script>"""


def _inject_js_if_html(
    resp_headers: dict[str, str], resp_body: bytes
) -> tuple[bytes, dict[str, str]]:
    """Inject JS error collector into HTML responses. Returns (new_body, updated_headers)."""
    ct = resp_headers.get("content-type", "").lower()
    if "text/html" not in ct:
        return resp_body, resp_headers

    encoding = resp_headers.get("content-encoding", "").lower()
    body = resp_body
    modified_headers = dict(resp_headers)

    if "gzip" in encoding:
        import gzip as _gz
        try:
            body = _gz.decompress(resp_body)
            modified_headers.pop("content-encoding", None)
            modified_headers.pop("Content-Encoding", None)
        except Exception:
            return resp_body, resp_headers
    elif encoding and encoding not in ("identity", ""):
        return resp_body, resp_headers  # unknown encoding, skip

    lower = body.lower()
    idx = lower.rfind(b"</body>")
    if idx == -1:
        return resp_body, resp_headers

    body = body[:idx] + _JS_COLLECTOR_SNIPPET + body[idx:]
    modified_headers["content-length"] = str(len(body))
    return body, modified_headers


def _headers_dict_to_raw(headers: dict[str, str]) -> bytes:
    """Reconstruct raw header bytes from a dict (for after injection)."""
    return b"".join(
        f"{k}: {v}\r\n".encode("latin-1") for k, v in headers.items()
    )


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _parse_request_line(line: bytes) -> tuple[str, str, str]:
    parts = line.decode("latin-1").rstrip("\r\n").split(" ", 2)
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    return "GET", "/", "HTTP/1.1"


def _parse_headers(raw: bytes) -> dict[str, str]:
    """Parse response headers — last value wins except Set-Cookie which is joined."""
    headers: dict[str, str] = {}
    set_cookies: list[str] = []
    for line in raw.split(b"\r\n"):
        if b":" in line:
            k, _, v = line.partition(b":")
            key = k.strip().decode("latin-1").lower()
            val = v.strip().decode("latin-1")
            if key == "set-cookie":
                set_cookies.append(val)
            else:
                headers[key] = val
    if set_cookies:
        headers["set-cookie"] = "\n".join(set_cookies)
    return headers


async def _read_headers(reader: asyncio.StreamReader) -> tuple[bytes, dict[str, str]]:
    lines: list[bytes] = []
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=15.0)
        if not line or line in (b"\r\n", b"\n"):
            break
        lines.append(line)
    raw = b"".join(lines)
    return raw, _parse_headers(raw)


async def _read_body(reader: asyncio.StreamReader, headers: dict[str, str]) -> bytes:
    """Lit le body selon Content-Length ou Transfer-Encoding: chunked."""
    te = headers.get("transfer-encoding", "").lower()
    if "chunked" in te:
        return await _read_chunked_body(reader)
    cl = int(headers.get("content-length", "0") or "0")
    if cl > 0:
        return await asyncio.wait_for(reader.read(cl), timeout=30.0)
    return b""


async def _read_chunked_body(reader: asyncio.StreamReader) -> bytes:
    """Lit un body en Transfer-Encoding: chunked et le décode."""
    chunks: list[bytes] = []
    try:
        while True:
            size_line = await asyncio.wait_for(reader.readline(), timeout=15.0)
            size_str = size_line.decode("latin-1").strip().split(";")[0]
            chunk_size = int(size_str, 16)
            if chunk_size == 0:
                # Lire les trailers éventuels jusqu'à ligne vide
                while True:
                    trailer = await asyncio.wait_for(reader.readline(), timeout=5.0)
                    if trailer in (b"\r\n", b"\n", b""):
                        break
                break
            # readexactly garantit la lecture de chunk_size octets exacts.
            # reader.read(n) peut retourner moins d'octets sur lecture TCP partielle,
            # ce qui corrompt le CRLF séparateur suivant.
            chunk = await asyncio.wait_for(reader.readexactly(chunk_size), timeout=30.0)
            chunks.append(chunk)
            await asyncio.wait_for(reader.readline(), timeout=5.0)  # CRLF après chunk
    except Exception:
        pass
    return b"".join(chunks)


async def _pipe(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    try:
        while True:
            data = await asyncio.wait_for(reader.read(65536), timeout=30.0)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass


# ── Main proxy class ──────────────────────────────────────────────────────────

class HDWPProxy:
    """Lightweight asyncio MITM HTTP/HTTPS proxy — replaces mitmproxy."""

    def __init__(
        self,
        bus: AsyncEventBus,
        scope_guard: ScopeGuard,
        session_id: str,
        host: str = "127.0.0.1",
        port: int = 8080,
        role_name: str = "anonymous",
    ) -> None:
        self._bus = bus
        self._scope_guard = scope_guard
        self._session_id = session_id
        self._host = host
        self._port = port
        self._role_name = role_name
        self._server: asyncio.Server | None = None
        self._running = False
        self._seen_tokens: set[str] = set()
        self._capture_count = 0
        try:
            self._ca_cert, self._ca_key = _load_or_create_ca()
        except RuntimeError:
            self._ca_cert = self._ca_key = None

    @property
    def address(self) -> str:
        return f"{self._host}:{self._port}"

    async def start(self) -> None:
        if self._ca_cert is None:
            log.error("hdwp_proxy.no_ca_cannot_start")
            return
        self._running = True
        try:
            for _ in range(10):
                try:
                    self._server = await asyncio.start_server(
                        self._handle_client, self._host, self._port
                    )
                    break
                except OSError as exc:
                    if exc.errno != 98:  # EADDRINUSE
                        raise
                    log.warning("hdwp_proxy.port_in_use", port=self._port)
                    self._port += 1
            else:
                log.error("hdwp_proxy.no_port_available")
                return
            log.info("hdwp_proxy.started", address=self.address)
            async with self._server:
                await self._server.serve_forever()
        except OSError as exc:
            log.error("hdwp_proxy.bind_failed", port=self._port, error=str(exc))
        except Exception as exc:
            log.error("hdwp_proxy.start_failed", error=str(exc))
        finally:
            self._running = False
            log.info("hdwp_proxy.stopped")

    async def stop(self) -> None:
        self._running = False
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass

    # ── Connection dispatcher ─────────────────────────────────────────────────

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            first_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not first_line:
                return
            method, url, _ = _parse_request_line(first_line)
            if method.upper() == "CONNECT":
                await self._handle_connect(reader, writer, url)
            else:
                await self._handle_http(reader, writer, first_line, method, url)
        except TimeoutError:
            pass
        except Exception as exc:
            log.debug("hdwp_proxy.client_error", error=str(exc))
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── Plain HTTP ────────────────────────────────────────────────────────────

    async def _handle_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_line: bytes,
        method: str,
        url: str,
    ) -> None:
        headers_raw, headers = await _read_headers(reader)
        body = await _read_body(reader, headers)

        from hdwp.core.context.scope_guard import ScopeVerdict
        if self._scope_guard.check(url, method) != ScopeVerdict.ALLOWED:
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        parsed = urlparse(url)
        host = parsed.hostname or headers.get("host", "").split(":")[0]
        port = parsed.port or 80
        try:
            t_reader, t_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10.0
            )
        except Exception:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        req_path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        req_line = f"{method} {req_path} HTTP/1.1\r\n".encode()
        # Si le body a été décodé depuis un stream chunked, retirer le header
        # Transfer-Encoding et poser Content-Length pour que l'upstream ne
        # tente pas de relire le body déjà décodé comme un nouveau stream chunked.
        if "transfer-encoding" in {k.lower() for k in headers}:
            headers = {k: v for k, v in headers.items()
                       if k.lower() != "transfer-encoding"}
            headers["Content-Length"] = str(len(body))
            headers_raw = _headers_dict_to_raw(headers)
        t_writer.write(req_line + headers_raw + b"\r\n" + body)
        await t_writer.drain()

        try:
            resp_status = await asyncio.wait_for(t_reader.readline(), timeout=15.0)
            resp_headers_raw, resp_headers = await _read_headers(t_reader)
            resp_body = await _read_body(t_reader, resp_headers)
        except Exception:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            t_writer.close()
            try:
                await t_writer.wait_closed()
            except Exception:
                pass
            return

        # Inject JS collector into HTML responses
        resp_body, resp_headers = _inject_js_if_html(resp_headers, resp_body)
        resp_headers_raw = _headers_dict_to_raw(resp_headers)

        writer.write(resp_status + resp_headers_raw + b"\r\n" + resp_body)
        await writer.drain()
        t_writer.close()

        status_code = int(resp_status.split(b" ", 2)[1]) if len(resp_status.split(b" ")) >= 2 else 0
        await self._emit_observation(
            method, url, dict(headers), body,
            status_code, dict(resp_headers), resp_body,
        )

    # ── HTTPS CONNECT MITM ────────────────────────────────────────────────────

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host_port: str,
    ) -> None:
        await _read_headers(reader)

        host, _, port_str = host_port.partition(":")
        port = int(port_str) if port_str.isdigit() else 443

        # Vérifier le scope avant d'établir le tunnel
        from hdwp.core.context.scope_guard import ScopeVerdict
        probe_url = f"https://{host}:{port}/"
        if self._scope_guard.check(probe_url, "CONNECT") != ScopeVerdict.ALLOWED:
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()

        if sys.version_info < (3, 11):
            log.warning("hdwp_proxy.tls_requires_311", host=host)
            try:
                t_reader, t_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=10.0
                )
                await asyncio.gather(
                    _pipe(reader, t_writer),
                    _pipe(t_reader, writer),
                    return_exceptions=True,
                )
                t_writer.close()
            except Exception:
                pass
            return

        if self._ca_cert is None or self._ca_key is None:
            return

        try:
            cert_path, key_path = _gen_cert_for_host(host, self._ca_cert, self._ca_key)
        except Exception as exc:
            log.debug("hdwp_proxy.cert_gen_failed", host=host, error=str(exc))
            return

        ssl_srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_srv.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        ssl_srv.set_alpn_protocols(["http/1.1"])

        loop = asyncio.get_running_loop()
        try:
            transport = writer.transport
            protocol = transport.get_protocol()
            tls_transport = await loop.start_tls(
                transport, protocol, ssl_srv, server_side=True
            )
        except Exception as exc:
            log.debug("hdwp_proxy.tls_client_upgrade_failed", host=host, error=str(exc))
            return

        tls_reader = asyncio.StreamReader()
        tls_proto = asyncio.StreamReaderProtocol(tls_reader)
        tls_transport.set_protocol(tls_proto)
        # Python 3.12 a supprimé le paramètre `loop` de asyncio.StreamWriter.
        # On passe uniquement les 3 arguments requis (transport, protocol, reader).
        tls_writer = asyncio.StreamWriter(tls_transport, tls_proto, tls_reader)

        ssl_cli = ssl.create_default_context()
        ssl_cli.set_alpn_protocols(["http/1.1"])
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_cli, server_hostname=host),
                timeout=10.0,
            )
        except Exception as exc:
            log.debug("hdwp_proxy.upstream_failed", host=host, error=str(exc))
            try:
                tls_writer.close()
            except Exception:
                pass
            return

        try:
            await self._intercept_https(tls_reader, tls_writer, up_reader, up_writer, host)
        finally:
            up_writer.close()
            try:
                tls_writer.close()
            except Exception:
                pass

    async def _intercept_https(
        self,
        c_reader: asyncio.StreamReader,
        c_writer: asyncio.StreamWriter,
        u_reader: asyncio.StreamReader,
        u_writer: asyncio.StreamWriter,
        host: str,
    ) -> None:
        from hdwp.core.context.scope_guard import ScopeVerdict

        while True:
            try:
                first_line = await asyncio.wait_for(c_reader.readline(), timeout=30.0)
                if not first_line:
                    break
                method, path, _ = _parse_request_line(first_line)
                headers_raw, headers = await _read_headers(c_reader)
                body = await _read_body(c_reader, headers)
            except Exception:
                break

            url = f"https://{host}{path}"
            in_scope = self._scope_guard.check(url, method) == ScopeVerdict.ALLOWED

            u_writer.write(first_line + headers_raw + b"\r\n" + body)
            try:
                await u_writer.drain()
            except Exception:
                break

            try:
                resp_line = await asyncio.wait_for(u_reader.readline(), timeout=30.0)
                resp_headers_raw, resp_headers = await _read_headers(u_reader)
                resp_body = await _read_body(u_reader, resp_headers)
            except Exception:
                break

            # Inject JS collector into HTML responses
            resp_body, resp_headers = _inject_js_if_html(resp_headers, resp_body)
            resp_headers_raw = _headers_dict_to_raw(resp_headers)

            c_writer.write(resp_line + resp_headers_raw + b"\r\n" + resp_body)
            try:
                await c_writer.drain()
            except Exception:
                break

            if in_scope and resp_line:
                try:
                    status_code = int(resp_line.split(b" ", 2)[1])
                except Exception:
                    status_code = 0
                await self._emit_observation(
                    method, url, dict(headers), body,
                    status_code, dict(resp_headers), resp_body,
                )

            conn = headers.get("connection", "").lower()
            resp_conn = resp_headers.get("connection", "").lower()
            if conn == "close" or resp_conn == "close":
                break

    # ── Observation emission ──────────────────────────────────────────────────

    async def _emit_observation(
        self,
        method: str,
        url: str,
        req_headers: dict[str, str],
        req_body: bytes,
        status_code: int,
        resp_headers: dict[str, str],
        resp_body: bytes,
    ) -> None:
        try:
            body_json: dict | None = json.loads(
                resp_body.decode("utf-8", errors="replace")
            ) if resp_body else None
        except Exception:
            body_json = None

        combined_headers = {**req_headers, **resp_headers}
        token_info = _extract_auth_token(body_json, combined_headers)
        if token_info:
            token_val = token_info[1]
            if token_val not in self._seen_tokens:
                self._seen_tokens.add(token_val)
                self._capture_count += 1
                await self._bus.emit(
                    CREDENTIALS_CAPTURED,
                    {
                        "token_type": token_info[0],
                        "token_value": token_val,
                        "role_name": f"captured_{self._capture_count}",
                        "source_url": url,
                    },
                    source="hdwp_proxy",
                )
                log.info(
                    "proxy.credential_captured",
                    role=f"captured_{self._capture_count}",
                    url=url,
                )

        norm_req = normalize_request(
            method=method,
            url=url,
            headers=req_headers,
            body=req_body.decode("utf-8", errors="replace") if req_body else None,
        )
        norm_resp = normalize_response(
            status_code=status_code,
            headers=resp_headers,
            body=resp_body.decode("utf-8", errors="replace") if resp_body else None,
        )
        obs = RawObservation(
            timestamp=datetime.datetime.now(datetime.UTC).isoformat(),
            source="passive",
            type=ObservationType.HTTP,
            request=norm_req,
            response=norm_resp,
            session_id=self._session_id,
            tags=[f"role:{self._role_name}", "source:hdwp_proxy"],
        )
        await self._bus.emit(OBSERVATION_RAW, obs.model_dump(), source="hdwp_proxy")
