"""auth_failure_logging.py"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Optional, Protocol
from urllib.parse import parse_qsl

from sqlalchemy import JSON, DateTime, Index, Integer, String, delete
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

logger = logging.getLogger("auth_failures")

REDACTED = "[REDACTED]"
MAX_STR_LEN = 500      # limita o tamanho de cada valor registrado
MAX_ITEMS = 100        # limita itens por dict/lista
MAX_DEPTH = 6

# Chaves cujo valor NUNCA deve ser persistido (headers, query, JSON, formulários).
_SENSITIVE_KEY = re.compile(
    r"(pass(word|wd)?|senha|secret|token|authorization|cookie|api[-_]?key|"
    r"otp|mfa|2fa|cvv|credential|signature|session|(^|[-_])code$)",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# Redação de dados sensíveis
# --------------------------------------------------------------------------- #
def redact(value: Any, key: Optional[str] = None, depth: int = 0) -> Any:
    """Remove recursivamente valores sensíveis e limita o tamanho do que é guardado."""
    if key is not None and _SENSITIVE_KEY.search(key):
        return REDACTED
    if depth > MAX_DEPTH:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {
            str(k)[:100]: redact(v, str(k), depth + 1)
            for k, v in list(value.items())[:MAX_ITEMS]
        }
    if isinstance(value, (list, tuple)):
        return [redact(v, None, depth + 1) for v in list(value)[:MAX_ITEMS]]
    if isinstance(value, str):
        return value if len(value) <= MAX_STR_LEN else value[:MAX_STR_LEN] + "…"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:MAX_STR_LEN]


def _pairs_to_dict(pairs: Iterable[tuple[str, str]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in list(pairs)[:MAX_ITEMS]:
        if k in out:
            out[k] = out[k] + [v] if isinstance(out[k], list) else [out[k], v]
        else:
            out[k] = v
    return out


def _redact_headers(raw_headers: dict[str, str]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for name, value in raw_headers.items():
        if name == "authorization":
            # mantém apenas o esquema (Bearer/Basic) para diagnóstico
            scheme = value.split(" ", 1)[0][:20] if value else ""
            safe[name] = f"{scheme} {REDACTED}".strip()
        else:
            safe[name] = redact(value, name)
    return safe


def _parse_body(body: bytes, content_type: str, truncated: bool) -> tuple[Any, Optional[str]]:
    """Retorna (corpo_redigido, observação)."""
    if not body:
        return None, None
    if truncated:
        return None, "body_exceeded_limit_not_logged"

    ctype = content_type.split(";")[0].strip().lower()
    try:
        if ctype == "application/json" or ctype.endswith("+json"):
            return redact(json.loads(body.decode("utf-8"))), None
        if ctype == "application/x-www-form-urlencoded":
            pairs = parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True)
            return redact(_pairs_to_dict(pairs)), None
    except (ValueError, UnicodeDecodeError):
        return None, "body_unparseable"
    return None, f"content_type_not_logged:{ctype or 'unknown'}"


# --------------------------------------------------------------------------- #
# Persistência (consultável pelo suporte)
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class AuthFailureLog(Base):
    __tablename__ = "auth_failure_log"
    __table_args__ = (
        Index("ix_authfail_tenant_time", "tenant_hint", "occurred_at"),
        Index("ix_authfail_ip_time", "client_ip", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    request_id: Mapped[str] = mapped_column(String(36), unique=True)
    # Informado pelo cliente antes da autenticação: NÃO é verificado.
    tenant_hint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    client_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(2048))
    status_code: Mapped[int] = mapped_column(Integer)
    query_params: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    headers: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    body: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    body_note: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)


class AuthFailureSink(Protocol):
    async def write(self, record: dict[str, Any]) -> None: ...


class SQLAlchemyAuthFailureSink:
    """Grava na tabela compartilhada (sessão síncrona executada em thread)."""

    def __init__(self, session_factory: "sessionmaker[Session]") -> None:
        self._session_factory = session_factory

    async def write(self, record: dict[str, Any]) -> None:
        await asyncio.to_thread(self._insert, record)

    def _insert(self, record: dict[str, Any]) -> None:
        with self._session_factory() as session, session.begin():
            session.add(AuthFailureLog(**record))

    def purge_older_than(self, days: int) -> int:
        """Retenção: rode periodicamente (cron/worker)."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        with self._session_factory() as session, session.begin():
            return session.execute(
                delete(AuthFailureLog).where(AuthFailureLog.occurred_at < cutoff)
            ).rowcount


# --------------------------------------------------------------------------- #
# Utilitários de requisição
# --------------------------------------------------------------------------- #
TenantResolver = Callable[[dict, dict[str, str], Any], Optional[str]]


def default_tenant_resolver(scope: dict, headers: dict[str, str], body: Any) -> Optional[str]:
    return headers.get("x-tenant-id")


def _client_ip(scope: dict, headers: dict[str, str], trusted: frozenset[str]) -> Optional[str]:
    peer = (scope.get("client") or (None, None))[0]
    if not peer or peer not in trusted:
        return peer  # só confia em X-Forwarded-For vindo de proxies conhecidos
    for ip in reversed([p.strip() for p in headers.get("x-forwarded-for", "").split(",") if p.strip()]):
        if ip in trusted:
            continue
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError:
            return peer
    return peer


# --------------------------------------------------------------------------- #
# Middleware
# --------------------------------------------------------------------------- #
class AuthFailureLoggingMiddleware:
    def __init__(
        self,
        app,
        sink: AuthFailureSink,
        *,
        failure_statuses: Iterable[int] = (401,),
        login_paths: Iterable[str] = (),
        login_failure_statuses: Iterable[int] = (400, 401, 403),
        max_body_bytes: int = 16 * 1024,
        trusted_proxies: Iterable[str] = (),
        tenant_resolver: TenantResolver = default_tenant_resolver,
    ) -> None:
        self.app = app
        self.sink = sink
        self.failure_statuses = frozenset(failure_statuses)
        self.login_paths = frozenset(p.rstrip("/") or "/" for p in login_paths)
        self.login_failure_statuses = frozenset(login_failure_statuses)
        self.max_body_bytes = max_body_bytes
        self.trusted_proxies = frozenset(trusted_proxies)
        self.tenant_resolver = tenant_resolver

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 1) Lê (até o limite) e guarda o corpo para poder reenviá-lo à aplicação.
        messages, body, truncated = await self._buffer_body(receive)
        pending = list(messages)

        async def replay_receive():
            if pending:
                return pending.pop(0)
            return await receive()

        # 2) Observa o status da resposta sem alterá-la.
        status: dict[str, int] = {}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        await self.app(scope, replay_receive, send_wrapper)

        # 3) Se foi falha de autenticação, registra (sem nunca afetar a resposta).
        code = status.get("code")
        if code is not None and self._is_auth_failure(scope.get("path", ""), code):
            await self._record(scope, body, truncated, code)

    # ---- helpers ---------------------------------------------------------- #
    def _is_auth_failure(self, path: str, code: int) -> bool:
        if code in self.failure_statuses:
            return True
        return (path.rstrip("/") or "/") in self.login_paths and code in self.login_failure_statuses

    async def _buffer_body(self, receive):
        messages: list[dict] = []
        body = bytearray()
        truncated = False
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] != "http.request":  # ex.: http.disconnect
                break
            chunk = message.get("body", b"")
            room = self.max_body_bytes - len(body)
            if room > 0:
                body.extend(chunk[:room])
            if len(chunk) > room:
                truncated = True
                break  # o restante passa direto pelo receive original
            if not message.get("more_body", False):
                break
        return messages, bytes(body), truncated

    async def _record(self, scope, body: bytes, truncated: bool, status_code: int) -> None:
        try:
            raw = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
            parsed_body, note = _parse_body(body, raw.get("content-type", ""), truncated)

            try:
                tenant = self.tenant_resolver(scope, raw, parsed_body)
            except Exception:  # resolver do cliente não pode derrubar o log
                tenant = None

            query = _pairs_to_dict(
                parse_qsl(scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True)
            )

            record = {
                "occurred_at": datetime.now(timezone.utc),
                "request_id": str(uuid.uuid4()),
                "tenant_hint": tenant[:128] if tenant else None,
                "client_ip": _client_ip(scope, raw, self.trusted_proxies),
                "user_agent": raw.get("user-agent", "")[:512] or None,
                "method": scope.get("method", "")[:10],
                "path": scope.get("path", "")[:2048],
                "status_code": status_code,
                "query_params": redact(query),
                "headers": _redact_headers(raw),
                "body": parsed_body,
                "body_note": note,
            }
        except Exception:
            logger.exception("Falha ao montar registro de autenticação malsucedida")
            return

        try:
            await self.sink.write(record)
        except Exception:
            # Fallback: o registro já está redigido, então pode ir para o log da aplicação.
            logger.exception("Falha ao persistir registro; usando fallback")
            logger.warning("auth_failure %s", json.dumps(record, default=str, ensure_ascii=False))