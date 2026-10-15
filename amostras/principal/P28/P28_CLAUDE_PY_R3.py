"""
Middleware de verificação de assinatura para SaaS multilocatário.

A cada requisição:
  1. identifica a empresa (tenant) a partir da identidade JÁ AUTENTICADA;
  2. consulta o serviço externo de faturamento;
  3. libera ou bloqueia o acesso conforme o status da assinatura.

Dependências: fastapi, httpx
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Iterable

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("subscription")

# Status do faturamento que concedem acesso.
ACTIVE_STATUSES = frozenset({"active", "trialing"})


class BillingUnavailableError(Exception):
    """Serviço de faturamento indisponível, lento ou com resposta inválida."""


@dataclass(frozen=True)
class SubscriptionInfo:
    tenant_id: str
    status: str

    @property
    def is_active(self) -> bool:
        return self.status in ACTIVE_STATUSES


class BillingClient:
    """Cliente HTTP do serviço externo de faturamento.

    Contrato assumido: GET {base_url}/subscriptions/{tenant_id}
      200 -> {"status": "active" | "trialing" | "past_due" | "canceled" | ...}
      404 -> empresa sem assinatura
    Ajuste conforme o contrato real do seu provedor.
    """

    def __init__(self, base_url: str, api_key: str, timeout: float = 2.0) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=httpx.Timeout(timeout),
        )

    async def get_subscription(self, tenant_id: str) -> SubscriptionInfo:
        try:
            resp = await self._client.get(f"/subscriptions/{tenant_id}")
        except httpx.HTTPError as exc:
            raise BillingUnavailableError(f"falha de rede: {exc!r}") from exc

        if resp.status_code == 404:
            return SubscriptionInfo(tenant_id, "none")
        if resp.status_code != 200:
            raise BillingUnavailableError(f"status HTTP {resp.status_code}")

        try:
            status = str(resp.json()["status"]).lower()
        except (ValueError, KeyError, TypeError) as exc:
            raise BillingUnavailableError("resposta inválida") from exc
        return SubscriptionInfo(tenant_id, status)

    async def aclose(self) -> None:
        await self._client.aclose()


class _TTLCache:
    """Cache em memória com TTL curto. ttl <= 0 desativa (consulta a cada requisição)."""

    def __init__(self, ttl: float) -> None:
        self._ttl = ttl
        self._data: dict[str, tuple[float, SubscriptionInfo]] = {}

    def get(self, key: str) -> SubscriptionInfo | None:
        if self._ttl <= 0:
            return None
        item = self._data.get(key)
        if item and item[0] > time.monotonic():
            return item[1]
        self._data.pop(key, None)
        return None

    def set(self, key: str, value: SubscriptionInfo) -> None:
        if self._ttl > 0:
            self._data[key] = (time.monotonic() + self._ttl, value)


class SubscriptionMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        billing_client: BillingClient,
        exempt_prefixes: Iterable[str] = (
            "/health",
            "/docs",
            "/openapi.json",
            "/auth",        # login/refresh
            "/billing",     # permite que o cliente bloqueado regularize o pagamento
            "/webhooks",    # callbacks do próprio faturamento
        ),
        cache_ttl_seconds: float = 30.0,
        fail_open: bool = False,
    ) -> None:
        super().__init__(app)
        self._billing = billing_client
        self._exempt = tuple(exempt_prefixes)
        self._cache = _TTLCache(cache_ttl_seconds)
        self._fail_open = fail_open

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        path = request.url.path
        if request.method == "OPTIONS" or path.startswith(self._exempt):
            return await call_next(request)

        # O tenant DEVE vir da identidade autenticada (ex.: claim do JWT validado
        # por um middleware anterior), nunca de header/query/body do cliente.
        tenant_id = getattr(request.state, "tenant_id", None)
        if not tenant_id:
            return _error(401, "unauthenticated", "Empresa não identificada.")

        try:
            sub = self._cache.get(tenant_id)
            if sub is None:
                sub = await self._billing.get_subscription(tenant_id)
                self._cache.set(tenant_id, sub)
        except BillingUnavailableError as exc:
            logger.error("Faturamento indisponível (tenant=%s): %s", tenant_id, exc)
            if self._fail_open:
                logger.warning("fail-open: acesso liberado (tenant=%s)", tenant_id)
                return await call_next(request)
            return _error(
                503, "billing_unavailable",
                "Não foi possível validar a assinatura. Tente novamente em instantes.",
            )

        if not sub.is_active:
            logger.info("Acesso bloqueado (tenant=%s, status=%s)", tenant_id, sub.status)
            return _error(
                402, "subscription_inactive",
                "A assinatura da empresa não está ativa.",
            )

        return await call_next(request)


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": code, "message": message})


# ---------------------------------------------------------------------------
# Exemplo de uso
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import os

    import uvicorn
    from fastapi import FastAPI

    app = FastAPI()
    billing = BillingClient(
        base_url=os.environ["BILLING_URL"],
        api_key=os.environ["BILLING_API_KEY"],
    )

    # Ordem importa no Starlette: o ÚLTIMO middleware adicionado é o mais externo
    # (executa primeiro). Portanto, adicione a assinatura ANTES da autenticação,
    # para que request.state.tenant_id já esteja preenchido quando ela rodar.
    app.add_middleware(
        SubscriptionMiddleware,
        billing_client=billing,
        cache_ttl_seconds=30,   # use 0 para consultar o faturamento a CADA requisição
        fail_open=False,        # fail-closed: se o faturamento cair, bloqueia
    )
    # app.add_middleware(AuthMiddleware)  # <- valida o JWT e define request.state.tenant_id

    @app.on_event("shutdown")
    async def _close() -> None:
        await billing.aclose()

    @app.get("/health")
    async def health():
        return {"ok": True}

    uvicorn.run(app, host="0.0.0.0", port=8000)