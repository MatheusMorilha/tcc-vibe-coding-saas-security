"""
subscription_middleware.py

Middleware ASGI que, a cada requisição, verifica se a assinatura da empresa
cliente (tenant) está ativa no serviço externo de faturamento.

Dependência: httpx (fixe a versão e audite com pip-audit/Dependabot - A06).

Premissas de segurança:
  * O tenant_id vem EXCLUSIVAMENTE da identidade já autenticada
    (scope["state"]["tenant_id"], preenchido por um middleware de autenticação
    que valida o JWT/sessão). Nunca de headers, query string ou corpo.
  * Falha fechada: qualquer erro/ambiguidade bloqueia o acesso.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable, MutableMapping
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger("saas.subscription")

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

MAX_BILLING_RESPONSE_BYTES = 16 * 1024  # evita respostas gigantes (DoS)


# --------------------------------------------------------------------------- #
# Configuração
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class BillingConfig:
    base_url: str
    api_key: str = field(repr=False)  # repr=False: nunca vaza em logs/tracebacks
    timeout_s: float = 2.0
    cache_ttl_active_s: float = 60.0    # janela máxima para refletir um cancelamento
    cache_ttl_inactive_s: float = 10.0  # reativações valem rápido
    cache_max_entries: int = 10_000
    active_statuses: frozenset[str] = frozenset({"active", "trialing"})

    def __post_init__(self) -> None:
        parts = urlsplit(self.base_url)
        # A02/A10: somente HTTPS e host fixo vindo da configuração (nunca do usuário)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("BILLING_BASE_URL deve ser uma URL https válida")
        if not self.api_key:
            raise ValueError("BILLING_API_KEY não configurada")

    @classmethod
    def from_env(cls) -> "BillingConfig":
        # A02/A05: segredos via ambiente/secret manager, nunca no código
        return cls(
            base_url=os.environ["BILLING_BASE_URL"],
            api_key=os.environ["BILLING_API_KEY"],
        )


class BillingUnavailable(Exception):
    """Serviço de faturamento indisponível ou resposta inválida (falha fechada)."""


# --------------------------------------------------------------------------- #
# Utilitários: cache TTL limitado e circuit breaker
# --------------------------------------------------------------------------- #
class _TTLCache:
    def __init__(self, max_size: int) -> None:
        self._data: "OrderedDict[uuid.UUID, tuple[float, bool]]" = OrderedDict()
        self._max = max_size

    def get(self, key: uuid.UUID) -> bool | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if expires_at <= time.monotonic():
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return value

    def set(self, key: uuid.UUID, value: bool, ttl: float) -> None:
        self._data[key] = (time.monotonic() + ttl, value)
        self._data.move_to_end(key)
        while len(self._data) > self._max:  # limite de memória
            self._data.popitem(last=False)

    def delete(self, key: uuid.UUID) -> None:
        self._data.pop(key, None)


class _CircuitBreaker:
    """Evita amplificar uma indisponibilidade do faturamento com mil timeouts."""

    def __init__(self, threshold: int = 5, reset_s: float = 10.0) -> None:
        self._threshold, self._reset_s = threshold, reset_s
        self._failures = 0
        self._open_until = 0.0

    def allow(self) -> bool:
        return time.monotonic() >= self._open_until

    def success(self) -> None:
        self._failures = 0

    def failure(self) -> None:
        self._failures += 1
        if self._failures >= self._threshold:
            self._open_until = time.monotonic() + self._reset_s
            self._failures = 0


# --------------------------------------------------------------------------- #
# Cliente do serviço de faturamento
# --------------------------------------------------------------------------- #
class SubscriptionChecker:
    def __init__(
        self, config: BillingConfig, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self._cfg = config
        self._cache = _TTLCache(config.cache_max_entries)
        self._breaker = _CircuitBreaker()
        self._inflight: dict[uuid.UUID, "asyncio.Future[bool]"] = {}
        self._client = httpx.AsyncClient(
            base_url=config.base_url,
            timeout=httpx.Timeout(config.timeout_s),
            follow_redirects=False,  # A10: sem redirecionamentos (SSRF)
            verify=True,             # A02: validação de certificado TLS
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
            headers={
                "Authorization": f"Bearer {config.api_key}",
                "Accept": "application/json",
                "User-Agent": "saas-platform/1.0",
            },
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    def invalidate(self, tenant_id: uuid.UUID) -> None:
        """Chame a partir do webhook autenticado do faturamento (cancelamento etc.)."""
        self._cache.delete(tenant_id)

    async def is_active(self, tenant_id: uuid.UUID) -> bool:
        cached = self._cache.get(tenant_id)
        if cached is not None:
            return cached

        # Single-flight: requisições simultâneas do mesmo tenant compartilham 1 chamada
        fut = self._inflight.get(tenant_id)
        if fut is None:
            fut = asyncio.ensure_future(self._fetch_and_cache(tenant_id))
            self._inflight[tenant_id] = fut
            fut.add_done_callback(lambda _f: self._inflight.pop(tenant_id, None))
        return await asyncio.shield(fut)

    async def _fetch_and_cache(self, tenant_id: uuid.UUID) -> bool:
        if not self._breaker.allow():
            raise BillingUnavailable("circuit breaker aberto")
        try:
            active = await self._query_billing(tenant_id)
        except BillingUnavailable:
            self._breaker.failure()
            raise
        except (httpx.HTTPError, ValueError) as exc:
            self._breaker.failure()
            raise BillingUnavailable(type(exc).__name__) from exc
        self._breaker.success()
        ttl = (
            self._cfg.cache_ttl_active_s if active else self._cfg.cache_ttl_inactive_s
        )
        self._cache.set(tenant_id, active, ttl)
        return active

    async def _query_billing(self, tenant_id: uuid.UUID) -> bool:
        # A03/A10: tenant_id é um UUID validado; str(UUID) é hex+hífens, seguro no path
        path = f"/v1/tenants/{tenant_id}/subscription"

        async with self._client.stream("GET", path) as resp:
            if resp.status_code == 404:
                return False  # tenant sem assinatura
            if resp.status_code != 200:
                # 401/403/5xx etc.: problema nosso ou do provedor -> falha fechada
                raise BillingUnavailable(f"status {resp.status_code}")
            if "application/json" not in resp.headers.get("content-type", ""):
                raise BillingUnavailable("content-type inesperado")

            body = bytearray()
            async for chunk in resp.aiter_bytes():
                body += chunk
                if len(body) > MAX_BILLING_RESPONSE_BYTES:
                    raise BillingUnavailable("resposta excede o limite")

        payload = json.loads(bytes(body))
        if not isinstance(payload, dict):
            raise BillingUnavailable("payload inválido")

        # A08: confere que a resposta se refere ao tenant consultado
        if payload.get("tenant_id") != str(tenant_id):
            raise BillingUnavailable("tenant_id divergente na resposta")

        status = payload.get("status")
        if not isinstance(status, str):
            raise BillingUnavailable("status ausente")
        return status in self._cfg.active_statuses  # lista de permissão explícita


# --------------------------------------------------------------------------- #
# Middleware ASGI
# --------------------------------------------------------------------------- #
class SubscriptionMiddleware:
    """
    Deve ser executado DEPOIS do middleware de autenticação, que precisa
    definir scope["state"]["tenant_id"] a partir de credenciais validadas.
    """

    def __init__(
        self,
        app: ASGIApp,
        checker: SubscriptionChecker,
        exempt_paths: Iterable[str] = (),
    ) -> None:
        self.app = app
        self.checker = checker
        # Comparação EXATA (sem startswith): evita bypass por prefixo/path traversal
        self.exempt_paths = frozenset(exempt_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):  # ex.: lifespan
            await self.app(scope, receive, send)
            return

        if scope["type"] == "http" and scope["path"] in self.exempt_paths:
            await self.app(scope, receive, send)
            return

        state = scope.setdefault("state", {})
        request_id = uuid.uuid4().hex  # gerado por nós: sem injeção de log via header

        # 1) Tenant vindo da identidade autenticada
        raw_tenant = state.get("tenant_id")
        if raw_tenant is None:
            logger.warning("tenant ausente no contexto", extra={"request_id": request_id})
            await self._reject(scope, send, 401, "unauthenticated", "Autenticação necessária.")
            return

        try:
            tenant_id = raw_tenant if isinstance(raw_tenant, uuid.UUID) else uuid.UUID(str(raw_tenant))
        except (ValueError, AttributeError, TypeError):
            logger.error("tenant_id malformado no contexto", extra={"request_id": request_id})
            await self._reject(scope, send, 403, "forbidden", "Acesso negado.")
            return

        # 2) Consulta (com cache/single-flight/circuit breaker) - falha fechada
        try:
            active = await self.checker.is_active(tenant_id)
        except BillingUnavailable as exc:
            logger.warning(
                "faturamento indisponível; acesso bloqueado (%s)", exc,
                extra={"request_id": request_id, "tenant_id": str(tenant_id)},
            )
            await self._reject(
                scope, send, 503, "billing_unavailable",
                "Não foi possível validar a assinatura. Tente novamente em instantes.",
                extra_headers=[(b"retry-after", b"15")],
            )
            return
        except Exception:  # A09/A04: erro inesperado também bloqueia, sem vazar detalhes
            logger.exception(
                "erro inesperado na verificação de assinatura",
                extra={"request_id": request_id, "tenant_id": str(tenant_id)},
            )
            await self._reject(scope, send, 503, "billing_unavailable",
                               "Não foi possível validar a assinatura.")
            return

        # 3) Decisão
        if not active:
            logger.info(
                "acesso negado: assinatura inativa",
                extra={"request_id": request_id, "tenant_id": str(tenant_id)},
            )
            await self._reject(scope, send, 402, "subscription_inactive",
                               "A assinatura da empresa não está ativa.")
            return

        state["tenant_id"] = tenant_id
        state["subscription_active"] = True
        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(
        scope: Scope,
        send: Send,
        status: int,
        code: str,
        message: str,
        extra_headers: list[tuple[bytes, bytes]] | None = None,
    ) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return

        body = json.dumps({"error": code, "message": message}).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"cache-control", b"no-store"),
            (b"x-content-type-options", b"nosniff"),
        ] + (extra_headers or [])
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})


# --------------------------------------------------------------------------- #
# Exemplo de uso (FastAPI)
# --------------------------------------------------------------------------- #
#
# from contextlib import asynccontextmanager
# from fastapi import FastAPI
#
# checker = SubscriptionChecker(BillingConfig.from_env())
#
# @asynccontextmanager
# async def lifespan(app):
#     yield
#     await checker.aclose()
#
# app = FastAPI(lifespan=lifespan)
#
# # add_middleware é LIFO: o último adicionado é o mais externo (roda primeiro).
# app.add_middleware(
#     SubscriptionMiddleware,
#     checker=checker,
#     exempt_paths={"/healthz", "/auth/login", "/webhooks/billing"},
# )
# app.add_middleware(AuthMiddleware)  # valida JWT e define request.state.tenant_id
# # (CORS, se usado, deve ficar ainda mais externo)