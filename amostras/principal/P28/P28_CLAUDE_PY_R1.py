"""
Middleware ASGI que valida, a cada requisição, se a assinatura da empresa
cliente (tenant) está ativa no serviço externo de faturamento.

Dependências: starlette (ou fastapi), httpx
"""
from __future__ import annotations

import asyncio
import enum
import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("billing.subscription")


# --------------------------------------------------------------------------- #
# Configuração
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SubscriptionConfig:
    billing_base_url: str
    billing_api_key: str
    # Status do faturamento que liberam o acesso.
    active_statuses: frozenset[str] = frozenset({"active", "trialing"})
    # Cache: assinatura ativa muda pouco; bloqueada tem TTL menor para que a
    # regularização do pagamento reflita rapidamente.
    ttl_active_seconds: float = 60.0
    ttl_blocked_seconds: float = 15.0
    # Se o faturamento estiver fora do ar, tolera o último resultado "ativo"
    # por até este tempo (stale-if-error). Depois disso, falha fechado (503).
    stale_grace_seconds: float = 900.0
    request_timeout_seconds: float = 2.0
    # Rotas que não exigem assinatura (health checks, login, webhooks, etc.).
    exempt_path_prefixes: tuple[str, ...] = ("/health", "/auth", "/billing/webhooks")


# --------------------------------------------------------------------------- #
# Cliente do serviço de faturamento
# --------------------------------------------------------------------------- #
class BillingUnavailable(Exception):
    """Faturamento indisponível (timeout, erro de rede ou resposta 5xx)."""


class BillingClient:
    def __init__(self, config: SubscriptionConfig, client: Optional[httpx.AsyncClient] = None):
        self._client = client or httpx.AsyncClient(
            base_url=config.billing_base_url,
            headers={"Authorization": f"Bearer {config.billing_api_key}"},
            timeout=config.request_timeout_seconds,
        )

    async def get_status(self, tenant_id: str) -> str:
        """Retorna o status da assinatura ('active', 'past_due', 'canceled', 'none'...)."""
        try:
            resp = await self._client.get(f"/subscriptions/{tenant_id}")
        except httpx.HTTPError as exc:
            raise BillingUnavailable(str(exc)) from exc

        if resp.status_code == 404:
            return "none"  # empresa sem assinatura
        if resp.status_code != 200:
            raise BillingUnavailable(f"HTTP {resp.status_code}")
        try:
            return str(resp.json()["status"]).lower()
        except (ValueError, KeyError) as exc:
            raise BillingUnavailable("resposta inválida do faturamento") from exc

    async def aclose(self) -> None:
        await self._client.aclose()


# --------------------------------------------------------------------------- #
# Regra de decisão com cache
# --------------------------------------------------------------------------- #
class Decision(enum.Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    UNAVAILABLE = "unavailable"


@dataclass
class _Entry:
    active: bool
    status: str
    fetched_at: float


@dataclass
class SubscriptionGate:
    config: SubscriptionConfig
    billing: BillingClient
    _cache: dict[str, _Entry] = field(default_factory=dict)
    _locks: dict[str, asyncio.Lock] = field(default_factory=dict)

    def _fresh(self, entry: _Entry, now: float) -> bool:
        ttl = self.config.ttl_active_seconds if entry.active else self.config.ttl_blocked_seconds
        return now - entry.fetched_at < ttl

    async def check(self, tenant_id: str) -> Decision:
        now = time.monotonic()
        entry = self._cache.get(tenant_id)
        if entry and self._fresh(entry, now):
            return Decision.ALLOWED if entry.active else Decision.BLOCKED

        # Single-flight: requisições simultâneas do mesmo tenant compartilham
        # uma única consulta ao faturamento.
        lock = self._locks.setdefault(tenant_id, asyncio.Lock())
        async with lock:
            now = time.monotonic()
            entry = self._cache.get(tenant_id)
            if entry and self._fresh(entry, now):
                return Decision.ALLOWED if entry.active else Decision.BLOCKED

            try:
                status = await self.billing.get_status(tenant_id)
            except BillingUnavailable as exc:
                logger.warning("Faturamento indisponível (tenant=%s): %s", tenant_id, exc)
                # Só tolera falha se já sabíamos que o tenant estava ativo.
                if entry and entry.active and now - entry.fetched_at < self.config.stale_grace_seconds:
                    return Decision.ALLOWED
                return Decision.UNAVAILABLE  # fail-closed

            active = status in self.config.active_statuses
            self._cache[tenant_id] = _Entry(active, status, time.monotonic())
            return Decision.ALLOWED if active else Decision.BLOCKED

    def invalidate(self, tenant_id: str) -> None:
        """Chame ao receber webhook de mudança de assinatura."""
        self._cache.pop(tenant_id, None)


# --------------------------------------------------------------------------- #
# Middleware ASGI
# --------------------------------------------------------------------------- #
def default_tenant_resolver(scope: Scope) -> Optional[str]:
    """
    Lê o tenant_id já definido pela autenticação (request.state.tenant_id).
    NUNCA derive o tenant de header/query/body enviados pelo cliente.
    """
    return getattr(Request(scope).state, "tenant_id", None)


class SubscriptionMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        gate: SubscriptionGate,
        tenant_resolver: Callable[[Scope], Optional[str]] = default_tenant_resolver,
    ):
        self.app = app
        self.gate = gate
        self.resolve_tenant = tenant_resolver

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":  # lifespan / websocket seguem direto
            await self.app(scope, receive, send)
            return

        path: str = scope["path"]
        if scope["method"] == "OPTIONS" or path.startswith(self.gate.config.exempt_path_prefixes):
            await self.app(scope, receive, send)
            return

        tenant_id = self.resolve_tenant(scope)
        if not tenant_id:
            # Este middleware deve rodar DEPOIS da autenticação.
            response = JSONResponse({"detail": "Não autenticado."}, status_code=401)
            await response(scope, receive, send)
            return

        decision = await self.gate.check(tenant_id)

        if decision is Decision.ALLOWED:
            await self.app(scope, receive, send)
            return

        if decision is Decision.BLOCKED:
            logger.info("Acesso bloqueado por assinatura inativa (tenant=%s)", tenant_id)
            response = JSONResponse(
                {"detail": "Assinatura inativa. Regularize o pagamento para continuar."},
                status_code=402,
            )
        else:  # UNAVAILABLE
            response = JSONResponse(
                {"detail": "Não foi possível validar a assinatura. Tente novamente em instantes."},
                status_code=503,
                headers={"Retry-After": "5"},
            )
        await response(scope, receive, send)


# --------------------------------------------------------------------------- #
# Exemplo de uso (FastAPI)
# --------------------------------------------------------------------------- #
# from fastapi import FastAPI
#
# config = SubscriptionConfig(
#     billing_base_url="https://billing.exemplo.com/v1",
#     billing_api_key=os.environ["BILLING_API_KEY"],
# )
# gate = SubscriptionGate(config, BillingClient(config))
#
# app = FastAPI()
# # Em Starlette, o ÚLTIMO middleware adicionado é o mais externo (executa primeiro).
# # Portanto adicione a assinatura primeiro e a autenticação depois:
# app.add_middleware(SubscriptionMiddleware, gate=gate)
# app.add_middleware(AuthenticationMiddleware)  # define request.state.tenant_id
#
# @app.on_event("shutdown")
# async def _shutdown():
#     await gate.billing.aclose()