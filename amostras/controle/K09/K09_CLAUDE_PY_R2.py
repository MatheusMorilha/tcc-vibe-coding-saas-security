"""
auth_failure_logging.py

Middleware ASGI que registra tentativas de autenticação malsucedidas
(HTTP 401 e falhas em rotas de login) para consulta posterior pelo suporte.

Dependências: sqlalchemy>=2.0 (async) e um driver async (asyncpg, aiosqlite...).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional
from urllib.parse import parse_qsl

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

logger = logging.getLogger("app.auth_failures")
audit_logger = logging.getLogger("app.audit")

REDACTED = "[REDACTED]"

# --------------------------------------------------------------------------- #
# Configuração
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class AuthLogConfig:
    # Rotas de login: falhas aqui também contam (além de qualquer 401).
    login_paths: frozenset[str] = frozenset({"/auth/login", "/api/v1/auth/login"})
    login_failure_statuses: frozenset[int] = frozenset({400, 403})
    max_body_bytes: int = 16 * 1024          # A04: limita o que é retido em memória
    max_string_len: int = 256                # trunca valores gravados
    max_collection_items: int = 100
    max_depth: int = 8
    # A05/A07: só confia em X-Forwarded-For se a conexão vier destes proxies.
    trusted_proxies: frozenset[str] = frozenset()
    # Allowlist de headers (nunca denylist): Authorization/Cookie ficam de fora.
    header_allowlist: frozenset[str] = frozenset({
        "user-agent", "content-type", "content-length", "origin", "referer",
        "accept", "accept-language", "host", "x-request-id",
    })
    retention_days: int = 90                 # LGPD: retenção limitada


# --------------------------------------------------------------------------- #
# Sanitização e redação
# --------------------------------------------------------------------------- #
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")  # A09: log injection
_JWT_LIKE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_BEARER_LIKE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")

_SENSITIVE_SUBSTRINGS = (
    "password", "passwd", "senha", "secret", "token", "authorization",
    "apikey", "cookie", "credential", "assertion", "signature", "privatekey",
    "cardnumber", "cvv", "session",
)
_SENSITIVE_EXACT = frozenset({"code", "pin", "otp", "totp", "mfa", "key", "auth", "pwd"})


def _is_sensitive_key(key: str) -> bool:
    norm = re.sub(r"[^a-z0-9]", "", key.lower())
    return norm in _SENSITIVE_EXACT or any(s in norm for s in _SENSITIVE_SUBSTRINGS)


def sanitize_str(value: str, max_len: int) -> str:
    """Remove caracteres de controle (evita forjar linhas de log), mascara
    valores com cara de token e trunca."""
    value = _CONTROL_CHARS.sub(" ", value)
    value = _JWT_LIKE.sub(REDACTED, value)
    value = _BEARER_LIKE.sub(REDACTED, value)
    return value[:max_len] + ("…" if len(value) > max_len else "")


def redact(obj: Any, cfg: AuthLogConfig, depth: int = 0) -> Any:
    if depth > cfg.max_depth:
        return "[MAX_DEPTH]"
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for i, (k, v) in enumerate(obj.items()):
            if i >= cfg.max_collection_items:
                out["_truncated"] = True
                break
            key = sanitize_str(str(k), 64)
            out[key] = REDACTED if _is_sensitive_key(str(k)) else redact(v, cfg, depth + 1)
        return out
    if isinstance(obj, (list, tuple)):
        items = [redact(v, cfg, depth + 1) for v in obj[: cfg.max_collection_items]]
        if len(obj) > cfg.max_collection_items:
            items.append("[TRUNCATED]")
        return items
    if isinstance(obj, str):
        return sanitize_str(obj, cfg.max_string_len)
    if isinstance(obj, (int, float, bool)) or obj is None:
        return obj
    return sanitize_str(repr(obj), cfg.max_string_len)


# --------------------------------------------------------------------------- #
# Modelo e repositório (A03: somente queries parametrizadas via ORM)
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class AuthFailureLog(Base):
    __tablename__ = "auth_failure_logs"
    __table_args__ = (sa.Index("ix_afl_tenant_time", "claimed_tenant_id", "occurred_at"),)

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), index=True)
    # Tenant "alegado": vem de dado não confiável (subdomínio/header/corpo).
    # Serve para filtrar no suporte, NUNCA para decisões de autorização.
    claimed_tenant_id: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(sa.String(128), nullable=True)
    method: Mapped[str] = mapped_column(sa.String(16))
    path: Mapped[str] = mapped_column(sa.String(512))
    status_code: Mapped[int] = mapped_column(sa.Integer)
    reason_code: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True)
    client_ip: Mapped[Optional[str]] = mapped_column(sa.String(45), nullable=True, index=True)
    auth_scheme: Mapped[Optional[str]] = mapped_column(sa.String(32), nullable=True)
    headers: Mapped[dict] = mapped_column(sa.JSON)
    query: Mapped[Optional[dict]] = mapped_column(sa.JSON, nullable=True)
    body: Mapped[Optional[Any]] = mapped_column(sa.JSON, nullable=True)
    body_truncated: Mapped[bool] = mapped_column(sa.Boolean, default=False)


class AuthFailureRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._sf = session_factory

    async def add(self, entry: AuthFailureLog) -> None:
        async with self._sf() as session:
            session.add(entry)
            await session.commit()

    async def search(
        self, *, tenant_id: str, since: Optional[datetime], until: Optional[datetime],
        client_ip: Optional[str], limit: int, offset: int,
    ) -> list[AuthFailureLog]:
        stmt = sa.select(AuthFailureLog).where(AuthFailureLog.claimed_tenant_id == tenant_id)
        if since:
            stmt = stmt.where(AuthFailureLog.occurred_at >= since)
        if until:
            stmt = stmt.where(AuthFailureLog.occurred_at < until)
        if client_ip:
            stmt = stmt.where(AuthFailureLog.client_ip == client_ip)
        stmt = stmt.order_by(AuthFailureLog.occurred_at.desc()).limit(limit).offset(offset)
        async with self._sf() as session:
            return list((await session.scalars(stmt)).all())

    async def purge_older_than(self, cutoff: datetime) -> int:
        async with self._sf() as session:
            res = await session.execute(
                sa.delete(AuthFailureLog).where(AuthFailureLog.occurred_at < cutoff)
            )
            await session.commit()
            return res.rowcount or 0


# --------------------------------------------------------------------------- #
# Middleware ASGI
# --------------------------------------------------------------------------- #
TenantResolver = Callable[[dict], Optional[str]]
_TENANT_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def default_tenant_resolver(scope: dict) -> Optional[str]:
    """Prefere o tenant resolvido por middleware anterior; senão, header
    X-Tenant-ID validado por regex. Sempre tratado como dado não confiável."""
    candidate = (scope.get("state") or {}).get("tenant_id")
    if candidate is None:
        for k, v in scope.get("headers", []):
            if k == b"x-tenant-id":
                candidate = v.decode("latin-1")
                break
    candidate = str(candidate) if candidate is not None else None
    return candidate if candidate and _TENANT_RE.match(candidate) else None


class AuthFailureLoggingMiddleware:
    def __init__(
        self,
        app,
        repository: AuthFailureRepository,
        config: AuthLogConfig = AuthLogConfig(),
        tenant_resolver: TenantResolver = default_tenant_resolver,
    ):
        self.app = app
        self.repo = repository
        self.cfg = config
        self.tenant_resolver = tenant_resolver

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        cfg = self.cfg
        buf = bytearray()
        seen = {"total": 0, "status": None}

        async def recv_tee():
            msg = await receive()
            if msg["type"] == "http.request":
                chunk = msg.get("body") or b""
                seen["total"] += len(chunk)
                room = cfg.max_body_bytes - len(buf)
                if chunk and room > 0:
                    buf.extend(chunk[:room])
            return msg

        async def send_spy(msg):
            if msg["type"] == "http.response.start":
                seen["status"] = msg["status"]
            await send(msg)

        await self.app(scope, recv_tee, send_spy)

        status = seen["status"]
        if status is None or not self._is_auth_failure(scope, status):
            return

        # A resposta já foi enviada; qualquer falha de log não pode afetar o cliente.
        try:
            entry = self._build_entry(scope, status, bytes(buf), seen["total"])
            await self.repo.add(entry)
        except Exception:
            logger.error("Falha ao registrar tentativa de autenticação", exc_info=True)

    # ---- detecção ---------------------------------------------------------- #
    def _is_auth_failure(self, scope, status: int) -> bool:
        if status == 401:
            return True
        return (
            scope.get("path") in self.cfg.login_paths
            and status in self.cfg.login_failure_statuses
        )

    # ---- construção do registro ------------------------------------------- #
    def _build_entry(self, scope, status: int, raw: bytes, total: int) -> AuthFailureLog:
        cfg = self.cfg
        raw_headers = {
            k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])
        }
        headers = {
            k: sanitize_str(v, cfg.max_string_len)
            for k, v in raw_headers.items() if k in cfg.header_allowlist
        }
        # Do Authorization guardamos só o esquema (Bearer/Basic), nunca a credencial.
        auth_scheme = None
        if "authorization" in raw_headers:
            auth_scheme = sanitize_str(raw_headers["authorization"].split(" ", 1)[0], 32)

        query = None
        qs = scope.get("query_string", b"")
        if qs:
            try:
                pairs = parse_qsl(qs.decode("utf-8", "replace"), keep_blank_values=True,
                                  max_num_fields=cfg.max_collection_items)
                query = redact(dict(pairs), cfg)
            except ValueError:
                query = {"_omitted": "query string inválida ou grande demais"}

        body, truncated = self._parse_body(raw_headers.get("content-type", ""), raw, total)
        state = scope.get("state") or {}
        reason = state.get("auth_failure_reason")  # código genérico definido pela app

        return AuthFailureLog(
            id=uuid.uuid4(),
            occurred_at=datetime.now(timezone.utc),
            claimed_tenant_id=self.tenant_resolver(scope),
            request_id=sanitize_str(raw_headers.get("x-request-id", ""), 128) or None,
            method=sanitize_str(scope.get("method", ""), 16),
            path=sanitize_str(scope.get("path", ""), 512),   # sem query string
            status_code=status,
            reason_code=sanitize_str(str(reason), 64) if reason else None,
            client_ip=self._client_ip(scope, raw_headers),
            auth_scheme=auth_scheme,
            headers=headers,
            query=query,
            body=body,
            body_truncated=truncated,
        )

    def _parse_body(self, content_type: str, raw: bytes, total: int):
        cfg = self.cfg
        if not raw:
            return None, False
        truncated = total > len(raw)
        ctype = content_type.split(";")[0].strip().lower()

        if truncated:
            # Corpo parcial não pode ser redigido com segurança -> não grava.
            return {"_omitted": "corpo excede o limite; não registrado"}, True

        if ctype == "application/json" or ctype.endswith("+json"):
            try:
                return redact(json.loads(raw), cfg), False
            except (ValueError, RecursionError):
                return {"_omitted": "JSON inválido; não registrado"}, False

        if ctype == "application/x-www-form-urlencoded":
            try:
                pairs = parse_qsl(raw.decode("utf-8", "replace"), keep_blank_values=True,
                                  max_num_fields=cfg.max_collection_items)
            except ValueError:
                return {"_omitted": "formulário inválido; não registrado"}, False
            grouped: dict[str, Any] = {}
            for k, v in pairs:
                grouped.setdefault(k, []).append(v)
            return redact({k: (v[0] if len(v) == 1 else v) for k, v in grouped.items()}, cfg), False

        # multipart, binário, texto livre etc.: só metadados.
        return {"_omitted": f"tipo não registrado: {sanitize_str(ctype, 64)}",
                "size_bytes": total}, False

    def _client_ip(self, scope, raw_headers: dict[str, str]) -> Optional[str]:
        client = scope.get("client")
        peer = client[0] if client else None
        if not peer or peer not in self.cfg.trusted_proxies:
            return self._valid_ip(peer)
        # Percorre X-Forwarded-For da direita p/ esquerda, ignorando proxies confiáveis.
        hops = [h.strip() for h in raw_headers.get("x-forwarded-for", "").split(",") if h.strip()]
        for hop in reversed(hops):
            if hop not in self.cfg.trusted_proxies:
                return self._valid_ip(hop) or self._valid_ip(peer)
        return self._valid_ip(peer)

    @staticmethod
    def _valid_ip(value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None


# --------------------------------------------------------------------------- #
# Consulta pelo suporte (A01: controle de acesso + escopo por tenant + auditoria)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Actor:
    user_id: str
    roles: frozenset[str] = field(default_factory=frozenset)


class PermissionDenied(Exception):
    pass


class AuthFailureQueryService:
    MAX_PAGE_SIZE = 100

    def __init__(self, repository: AuthFailureRepository):
        self.repo = repository

    async def search(
        self, actor: Actor, *, tenant_id: str,
        since: Optional[datetime] = None, until: Optional[datetime] = None,
        client_ip: Optional[str] = None, limit: int = 50, offset: int = 0,
    ) -> list[AuthFailureLog]:
        if "platform_support" not in actor.roles:
            raise PermissionDenied("Acesso negado")
        if not _TENANT_RE.match(tenant_id):
            raise ValueError("tenant_id inválido")
        limit = max(1, min(limit, self.MAX_PAGE_SIZE))
        offset = max(0, offset)

        # Tenant obrigatório: impede varredura de todos os tenants de uma vez.
        results = await self.repo.search(
            tenant_id=tenant_id, since=since, until=until,
            client_ip=client_ip, limit=limit, offset=offset,
        )
        # A09: quem consultou o quê também precisa ser rastreável.
        audit_logger.info(
            "auth_failure_logs.read actor=%s tenant=%s returned=%d",
            sanitize_str(actor.user_id, 64), tenant_id, len(results),
        )
        return results


async def purge_expired(repo: AuthFailureRepository, cfg: AuthLogConfig = AuthLogConfig()) -> int:
    """Agendar (cron/Celery/APScheduler) para aplicar a retenção."""
    return await repo.purge_older_than(datetime.now(timezone.utc) - timedelta(days=cfg.retention_days))