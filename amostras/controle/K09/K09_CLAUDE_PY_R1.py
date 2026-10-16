"""
auth_failure_log.py

Middleware ASGI que registra tentativas de autenticação malsucedidas
para consulta posterior pela equipe de suporte.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional, Protocol
from urllib.parse import parse_qsl

# Logger operacional (vai para o SIEM/stdout). Nunca recebe corpo da requisição.
ops_logger = logging.getLogger("security.auth_failures")

# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class FailedAuthLogConfig:
    # Rotas de autenticação monitoradas (comparação exata, sem prefixo).
    auth_paths: frozenset[str] = frozenset({"/auth/login", "/auth/token", "/auth/mfa/verify"})
    # Status HTTP considerados "falha de autenticação".
    failure_statuses: frozenset[int] = frozenset({401, 403})
    # Limite de corpo aceito nas rotas de auth (A04/DoS). Acima disso -> 413.
    max_body_bytes: int = 16 * 1024
    # Limites de sanitização do que é persistido.
    max_string_len: int = 256
    max_collection_items: int = 50
    max_depth: int = 5
    # Proxies reversos confiáveis (somente deles aceitamos X-Forwarded-For).
    trusted_proxies: tuple[str, ...] = ()
    # Headers permitidos no log (allowlist). Authorization/Cookie ficam de fora.
    header_allowlist: frozenset[str] = frozenset({
        "user-agent", "content-type", "content-length", "origin", "referer",
        "accept-language", "x-request-id", "x-tenant-id", "host",
    })
    tenant_header: str = "x-tenant-id"


# Chaves cujo valor jamais é persistido.
_SENSITIVE_KEY = re.compile(
    r"pass|pwd|senha|secret|token|otp|mfa|totp|code|codigo|cvv|pin|"
    r"auth|credential|assertion|signature|api[-_]?key|private|session|cookie",
    re.IGNORECASE,
)
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_SAFE_ID = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
_REDACTED = "[REDACTED]"

# --------------------------------------------------------------------------
# Sanitização (A03 - log injection / A02 - exposição de dados sensíveis)
# --------------------------------------------------------------------------

def _clean_str(value: str, limit: int) -> str:
    """Remove caracteres de controle (CR/LF etc.) e trunca."""
    value = _CONTROL_CHARS.sub("?", value)
    return value if len(value) <= limit else value[:limit] + "…[truncated]"


def _sanitize(value: Any, cfg: FailedAuthLogConfig, depth: int = 0) -> Any:
    if depth > cfg.max_depth:
        return "[MAX_DEPTH]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= cfg.max_collection_items:
                out["…"] = "[TRUNCATED]"
                break
            key = _clean_str(str(k), 64)
            out[key] = _REDACTED if _SENSITIVE_KEY.search(key) else _sanitize(v, cfg, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        items = [_sanitize(v, cfg, depth + 1) for v in value[: cfg.max_collection_items]]
        if len(value) > cfg.max_collection_items:
            items.append("[TRUNCATED]")
        return items
    if isinstance(value, str):
        return _clean_str(value, cfg.max_string_len)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _clean_str(repr(value), cfg.max_string_len)


def _sanitize_pairs(pairs: list[tuple[str, str]], cfg: FailedAuthLogConfig) -> dict[str, Any]:
    return _sanitize({k: v for k, v in pairs[: cfg.max_collection_items]}, cfg)


def _describe_body(body: bytes, content_type: str, cfg: FailedAuthLogConfig) -> dict[str, Any]:
    """
    Retorna uma representação segura do corpo. O corpo bruto NUNCA é salvo:
    se o parse falhar, não há como garantir que não contém credenciais.
    """
    if not body:
        return {"kind": "empty"}
    ct = content_type.split(";")[0].strip().lower()
    try:
        if ct == "application/json":
            return {"kind": "json", "data": _sanitize(json.loads(body), cfg)}
        if ct == "application/x-www-form-urlencoded":
            pairs = parse_qsl(
                body.decode("utf-8", errors="replace"),
                keep_blank_values=True,
                max_num_fields=cfg.max_collection_items,
            )
            return {"kind": "form", "data": _sanitize_pairs(pairs, cfg)}
    except (ValueError, RecursionError):
        return {"kind": "malformed", "content_type": _clean_str(ct, 64), "size": len(body)}
    return {"kind": "unsupported", "content_type": _clean_str(ct, 64), "size": len(body)}

# --------------------------------------------------------------------------
# Persistência
# --------------------------------------------------------------------------

class FailedAuthSink(Protocol):
    async def write(self, event: dict[str, Any]) -> None: ...


class SQLiteFailedAuthStore:
    """
    Implementação de referência. Em produção, troque por PostgreSQL mantendo
    SEMPRE consultas parametrizadas e uma role de banco com INSERT-only para
    a aplicação e SELECT para o serviço de suporte.
    """

    def __init__(self, path: str = "auth_failures.db") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._conn:
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS auth_failure_log (
                    id TEXT PRIMARY KEY,
                    occurred_at TEXT NOT NULL,
                    request_id TEXT,
                    claimed_tenant_id TEXT,
                    client_ip TEXT,
                    method TEXT,
                    path TEXT,
                    status INTEGER,
                    duration_ms INTEGER,
                    payload TEXT NOT NULL
                )"""
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_afl_tenant_time "
                "ON auth_failure_log (claimed_tenant_id, occurred_at)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_afl_ip_time "
                "ON auth_failure_log (client_ip, occurred_at)"
            )

    # -- escrita ------------------------------------------------------------
    def _insert(self, e: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO auth_failure_log "
                "(id, occurred_at, request_id, claimed_tenant_id, client_ip, "
                " method, path, status, duration_ms, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    e["id"], e["occurred_at"], e["request_id"], e["claimed_tenant_id"],
                    e["client_ip"], e["method"], e["path"], e["status"],
                    e["duration_ms"], json.dumps(e["payload"], ensure_ascii=True),
                ),
            )

    async def write(self, event: dict[str, Any]) -> None:
        await asyncio.to_thread(self._insert, event)

    # -- leitura (uso exclusivo do módulo de suporte) -------------------------
    def query(
        self,
        *,
        tenant_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        # Cláusulas são strings fixas; valores sempre via placeholders (A03).
        where, params = [], []
        if tenant_id:
            where.append("claimed_tenant_id = ?"); params.append(tenant_id)
        if client_ip:
            where.append("client_ip = ?"); params.append(client_ip)
        if since:
            where.append("occurred_at >= ?"); params.append(since.astimezone(timezone.utc).isoformat())
        if until:
            where.append("occurred_at <= ?"); params.append(until.astimezone(timezone.utc).isoformat())
        sql = (
            "SELECT id, occurred_at, request_id, claimed_tenant_id, client_ip, "
            "method, path, status, duration_ms, payload FROM auth_failure_log"
        )
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY occurred_at DESC LIMIT ? OFFSET ?"
        params += [max(1, min(limit, 200)), max(0, offset)]  # paginação limitada
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        cols = ["id", "occurred_at", "request_id", "claimed_tenant_id", "client_ip",
                "method", "path", "status", "duration_ms", "payload"]
        result = [dict(zip(cols, r)) for r in rows]
        for r in result:
            r["payload"] = json.loads(r["payload"])
        return result

    def purge_older_than(self, days: int) -> int:
        """Retenção/minimização de dados (LGPD). Agende em job periódico."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock, self._conn:
            return self._conn.execute(
                "DELETE FROM auth_failure_log WHERE occurred_at < ?", (cutoff,)
            ).rowcount

# --------------------------------------------------------------------------
# Middleware
# --------------------------------------------------------------------------

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


class FailedAuthLogMiddleware:
    def __init__(
        self,
        app: Callable[[Scope, Receive, Send], Awaitable[None]],
        sink: FailedAuthSink,
        config: FailedAuthLogConfig | None = None,
    ) -> None:
        self.app = app
        self.sink = sink
        self.cfg = config or FailedAuthLogConfig()
        self._proxies = [ipaddress.ip_network(p, strict=False) for p in self.cfg.trusted_proxies]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self._is_auth_request(scope):
            await self.app(scope, receive, send)
            return

        started = time.monotonic()

        # 1) Lê o corpo com limite e o reentrega à aplicação.
        body = await self._read_body(receive)
        if body is None:
            await self._reply(send, 413, b'{"detail":"Payload too large"}')
            return
        replayed = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        # 2) Captura o status da resposta sem alterá-la.
        status_holder: dict[str, int] = {}

        async def capture_send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
            await send(message)

        await self.app(scope, replay_receive, capture_send)

        # 3) Registra somente se foi falha de autenticação.
        status = status_holder.get("status")
        if status in self.cfg.failure_statuses:
            try:
                event = self._build_event(scope, body, status, started)
                ops_logger.warning(json.dumps({  # resumo sem corpo, p/ SIEM
                    k: event[k] for k in
                    ("id", "occurred_at", "claimed_tenant_id", "client_ip", "path", "status")
                }))
                await self.sink.write(event)
            except Exception:
                # Falha de log não pode derrubar o fluxo de auth; alerta sem payload.
                ops_logger.exception("Falha ao persistir log de autenticação")

    # -- auxiliares -----------------------------------------------------------
    def _is_auth_request(self, scope: Scope) -> bool:
        path = scope.get("path", "").rstrip("/") or "/"
        return scope.get("method") == "POST" and path in self.cfg.auth_paths

    async def _read_body(self, receive: Receive) -> Optional[bytes]:
        chunks: list[bytes] = []
        size = 0
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return b"".join(chunks)
            chunk = msg.get("body", b"")
            size += len(chunk)
            if size > self.cfg.max_body_bytes:
                return None
            chunks.append(chunk)
            if not msg.get("more_body"):
                return b"".join(chunks)

    @staticmethod
    async def _reply(send: Send, status: int, content: bytes) -> None:
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(content)).encode())]})
        await send({"type": "http.response.body", "body": content})

    def _client_ip(self, scope: Scope, headers: dict[str, str]) -> Optional[str]:
        client = scope.get("client")
        peer = client[0] if client else None
        try:
            peer_ip = ipaddress.ip_address(peer) if peer else None
        except ValueError:
            return None
        if peer_ip and any(peer_ip in net for net in self._proxies):
            # Percorre da direita p/ esquerda: primeiro IP não-proxy é o cliente.
            for candidate in reversed(headers.get("x-forwarded-for", "").split(",")):
                try:
                    ip = ipaddress.ip_address(candidate.strip())
                except ValueError:
                    continue
                if not any(ip in net for net in self._proxies):
                    return str(ip)
        return str(peer_ip) if peer_ip else None

    def _build_event(self, scope: Scope, body: bytes, status: int, started: float) -> dict[str, Any]:
        raw_headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }
        safe_headers = _sanitize(
            {k: v for k, v in raw_headers.items() if k in self.cfg.header_allowlist}, self.cfg
        )
        tenant = raw_headers.get(self.cfg.tenant_header, "")
        request_id = raw_headers.get("x-request-id", "")
        query_pairs = parse_qsl(
            scope.get("query_string", b"").decode("latin-1"),
            keep_blank_values=True,
            max_num_fields=self.cfg.max_collection_items,
        )
        return {
            "id": str(uuid.uuid4()),
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id if _SAFE_ID.match(request_id) else str(uuid.uuid4()),
            # Valor ALEGADO pelo cliente: serve p/ triagem, não para autorização.
            "claimed_tenant_id": tenant if _SAFE_ID.match(tenant) else None,
            "client_ip": self._client_ip(scope, raw_headers),
            "method": scope["method"],
            "path": _clean_str(scope["path"], 256),
            "status": status,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "payload": {
                "headers": safe_headers,
                "query": _sanitize_pairs(query_pairs, self.cfg),
                "body": _describe_body(body, raw_headers.get("content-type", ""), self.cfg),
            },
        }