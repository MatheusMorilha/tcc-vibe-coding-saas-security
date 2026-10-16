"""
subscription_guard.py

Middleware ASGI que, a cada requisição, verifica se a assinatura da empresa
cliente (tenant) está ativa no serviço externo de faturamento.

Dependências: starlette (ou fastapi), httpx, PyJWT[crypto]
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Iterable, Optional

import httpx
import jwt  # PyJWT
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("security.subscription")

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_MAX_TOKEN_LEN = 4096
_MAX_BILLING_RESPONSE_BYTES = 4096
_ALLOWED_STATUSES = frozenset({"active", "trialing"})  # liberam acesso
_KNOWN_STATUSES = frozenset(
    {"active", "trialing", "past_due", "canceled", "unpaid", "suspended", "expired"}
)


# --------------------------------------------------------------------------
# Configuração (A05: sem segredos no código; falha rápida se algo faltar)
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class GuardConfig:
    billing_base_url: str
    billing_api_key: str = field(repr=False)  # nunca aparece em logs/repr
    jwt_public_key: str = field(repr=False)
    jwt_issuer: str
    jwt_audience: str
    jwt_algorithms: tuple[str, ...] = ("RS256",)  # algoritmo fixado (A02/A07)
    cache_ttl_active: float = 15.0    # segundos; 0 = consulta a cada requisição
    cache_ttl_inactive: float = 5.0   # bloqueio é reavaliado mais rápido
    cache_max_entries: int = 10_000   # cache limitado (evita DoS por memória)

    def __post_init__(self) -> None:
        # A10 (SSRF) / A02: destino fixo, apenas HTTPS, sem credenciais na URL
        parts = __import__("urllib.parse").parse.urlsplit(self.billing_base_url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("BILLING_BASE_URL deve usar https")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("BILLING_BASE_URL inválida")

    @classmethod
    def from_env(cls) -> "GuardConfig":
        return cls(
            billing_base_url=os.environ["BILLING_BASE_URL"].rstrip("/"),
            billing_api_key=os.environ["BILLING_API_KEY"],
            jwt_public_key=os.environ["JWT_PUBLIC_KEY"],
            jwt_issuer=os.environ["JWT_ISSUER"],
            jwt_audience=os.environ["JWT_AUDIENCE"],
            cache_ttl_active=float(os.environ.get("BILLING_CACHE_TTL_ACTIVE", "15")),
            cache_ttl_inactive=float(os.environ.get("BILLING_CACHE_TTL_INACTIVE", "5")),
        )


# --------------------------------------------------------------------------
# Identificação do tenant (A01/A07): vem SOMENTE do token validado,
# nunca de header, query string ou corpo controlados pelo cliente.
# --------------------------------------------------------------------------
class AuthError(Exception):
    pass


def resolve_tenant_id(headers: Iterable[tuple[bytes, bytes]], cfg: GuardConfig) -> str:
    raw = next((v for k, v in headers if k.lower() == b"authorization"), None)
    if raw is None:
        raise AuthError("missing credentials")
    try:
        scheme, _, token = raw.decode("latin-1").partition(" ")
    except Exception as exc:  # pragma: no cover
        raise AuthError("malformed credentials") from exc
    if scheme.lower() != "bearer" or not token or len(token) > _MAX_TOKEN_LEN:
        raise AuthError("malformed credentials")
    try:
        claims = jwt.decode(
            token,
            cfg.jwt_public_key,
            algorithms=list(cfg.jwt_algorithms),  # impede alg=none / confusão HS/RS
            audience=cfg.jwt_audience,
            issuer=cfg.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "tid"]},
        )
    except jwt.PyJWTError as exc:
        raise AuthError("invalid token") from exc
    tenant_id = str(claims.get("tid", "")).lower()
    if not _UUID_RE.fullmatch(tenant_id):
        raise AuthError("invalid tenant claim")
    return tenant_id


# --------------------------------------------------------------------------
# Cliente do serviço de faturamento
# --------------------------------------------------------------------------
class BillingUnavailable(Exception):
    """Serviço de faturamento indisponível ou resposta inválida."""


@dataclass(frozen=True)
class Subscription:
    tenant_id: str
    status: str

    @property
    def is_active(self) -> bool:
        return self.status in _ALLOWED_STATUSES


class BillingClient:
    def __init__(self, cfg: GuardConfig, transport: Optional[httpx.AsyncBaseTransport] = None):
        self._client = httpx.AsyncClient(
            base_url=cfg.billing_base_url,
            headers={
                "Authorization": f"Bearer {cfg.billing_api_key}",
                "Accept": "application/json",
            },
            timeout=httpx.Timeout(connect=1.0, read=2.0, write=2.0, pool=1.0),
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
            follow_redirects=False,  # A10: sem redirecionamentos para outros hosts
            verify=True,             # A02: validação TLS sempre ligada
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def fetch(self, tenant_id: str) -> Subscription:
        # tenant_id já validado como UUID => seguro para compor o path (A03/A10)
        try:
            resp = await self._client.get(f"/v1/companies/{tenant_id}/subscription")
        except httpx.HTTPError as exc:
            raise BillingUnavailable(type(exc).__name__) from exc

        if resp.status_code == 404:
            return Subscription(tenant_id, "none")  # sem assinatura => bloqueia
        if resp.status_code != 200:
            raise BillingUnavailable(f"status {resp.status_code}")
        if len(resp.content) > _MAX_BILLING_RESPONSE_BYTES:
            raise BillingUnavailable("response too large")
        if "application/json" not in resp.headers.get("content-type", ""):
            raise BillingUnavailable("unexpected content-type")

        # A08: validação estrita do que veio de fora
        try:
            data = resp.json()
            status = data["status"]
            company_id = str(data["company_id"]).lower()
        except (ValueError, KeyError, TypeError) as exc:
            raise BillingUnavailable("invalid payload") from exc
        if company_id != tenant_id:
            # resposta de outra empresa: nunca confiar nela
            raise BillingUnavailable("tenant mismatch")
        if not isinstance(status, str) or status not in _KNOWN_STATUSES:
            return Subscription(tenant_id, "unknown")  # desconhecido => bloqueia
        return Subscription(tenant_id, status)


# --------------------------------------------------------------------------
# Cache TTL limitado + single-flight (evita avalanche de chamadas ao billing)
# --------------------------------------------------------------------------
class SubscriptionGuard:
    def __init__(self, cfg: GuardConfig, billing: Optional[BillingClient] = None):
        self.cfg = cfg
        self.billing = billing or BillingClient(cfg)
        self._cache: "OrderedDict[str, tuple[float, Subscription]]" = OrderedDict()
        self._inflight: dict[str, asyncio.Task] = {}

    async def aclose(self) -> None:
        await self.billing.aclose()

    def _cache_get(self, tenant_id: str) -> Optional[Subscription]:
        item = self._cache.get(tenant_id)
        if item is None:
            return None
        expires_at, sub = item
        if time.monotonic() >= expires_at:
            self._cache.pop(tenant_id, None)
            return None
        self._cache.move_to_end(tenant_id)
        return sub

    def _cache_set(self, sub: Subscription) -> None:
        ttl = self.cfg.cache_ttl_active if sub.is_active else self.cfg.cache_ttl_inactive
        if ttl <= 0:
            return
        self._cache[sub.tenant_id] = (time.monotonic() + ttl, sub)
        self._cache.move_to_end(sub.tenant_id)
        while len(self._cache) > self.cfg.cache_max_entries:
            self._cache.popitem(last=False)

    async def _fetch_and_store(self, tenant_id: str) -> Subscription:
        sub = await self.billing.fetch(tenant_id)
        self._cache_set(sub)  # falhas NÃO são cacheadas
        return sub

    async def check(self, tenant_id: str) -> Subscription:
        cached = self._cache_get(tenant_id)
        if cached is not None:
            return cached
        task = self._inflight.get(tenant_id)
        if task is None:
            task = asyncio.create_task(self._fetch_and_store(tenant_id))
            self._inflight[tenant_id] = task
            task.add_done_callback(lambda _t, k=tenant_id: self._inflight.pop(k, None))
        return await asyncio.shield(task)


# --------------------------------------------------------------------------
# Middleware ASGI
# --------------------------------------------------------------------------
class SubscriptionMiddleware:
    def __init__(self, app: ASGIApp, guard: SubscriptionGuard,
                 public_paths: Iterable[str] = ()):
        self.app = app
        self.guard = guard
        # Allowlist de caminhos EXATOS (sem prefixo/regex => sem bypass por path tricks)
        self.public_paths = frozenset(public_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)  # lifespan
            return
        if scope["type"] == "http" and scope["path"] in self.public_paths:
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex
        denial = await self._evaluate(scope, request_id)
        if denial is not None:
            status, code, extra = denial
            await self._deny(scope, send, status, code, request_id, extra)
            return
        await self.app(scope, receive, send)

    async def _evaluate(self, scope: Scope, request_id: str):
        """Retorna None se liberado, ou (status_http, codigo, headers_extras)."""
        # 1) Autenticação ANTES de qualquer chamada externa:
        #    requisições anônimas não geram tráfego para o billing.
        try:
            tenant_id = resolve_tenant_id(scope.get("headers", []), self.guard.cfg)
        except AuthError:
            logger.warning("auth_failed request_id=%s", request_id)
            return 401, "unauthorized", [(b"www-authenticate", b"Bearer")]

        # 2) Verificação da assinatura. Qualquer falha => fail closed (A04).
        try:
            sub = await self.guard.check(tenant_id)
        except BillingUnavailable as exc:
            logger.error("billing_unavailable tenant=%s request_id=%s reason=%s",
                         tenant_id, request_id, exc)
            return 503, "billing_unavailable", [(b"retry-after", b"5")]
        except Exception:
            logger.exception("billing_check_error tenant=%s request_id=%s",
                             tenant_id, request_id)
            return 503, "billing_unavailable", [(b"retry-after", b"5")]

        if not sub.is_active:
            # A09: evento de segurança/negócio auditável (só UUID e enum no log)
            logger.info("access_denied tenant=%s status=%s request_id=%s",
                        tenant_id, sub.status, request_id)
            return 402, "subscription_inactive", []

        # 3) Tenant confiável disponibilizado ao restante da aplicação.
        #    As consultas ao banco DEVEM filtrar por este valor (ou usar RLS).
        scope.setdefault("state", {})["tenant_id"] = tenant_id
        scope["state"]["request_id"] = request_id
        return None

    @staticmethod
    async def _deny(scope: Scope, send: Send, status: int, code: str,
                    request_id: str, extra: list[tuple[bytes, bytes]]) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        # Mensagem genérica: não revela detalhes internos (A05)
        body = json.dumps({"error": code, "request_id": request_id}).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"cache-control", b"no-store"),
            (b"x-content-type-options", b"nosniff"),
            (b"x-request-id", request_id.encode()),
            *extra,
        ]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})


# --------------------------------------------------------------------------
# Exemplo de uso (FastAPI)
# --------------------------------------------------------------------------
# from contextlib import asynccontextmanager
# from fastapi import FastAPI, Request
#
# guard = SubscriptionGuard(GuardConfig.from_env())
#
# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     yield
#     await guard.aclose()
#
# app = FastAPI(lifespan=lifespan)
# app.add_middleware(
#     SubscriptionMiddleware,
#     guard=guard,
#     public_paths={"/healthz", "/auth/login"},
# )
#
# @app.get("/invoices")
# async def invoices(request: Request):
#     tenant_id = request.state.tenant_id   # sempre filtrar queries por tenant_id
#     ...