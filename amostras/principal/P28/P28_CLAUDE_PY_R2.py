"""
Middleware de verificação de assinatura para plataforma SaaS multilocatária.

A cada requisição autenticada:
  1. Lê o tenant_id definido pelo middleware de autenticação (request.state.tenant_id).
  2. Consulta o serviço externo de faturamento (com cache curto e configurável).
  3. Libera ou bloqueia o acesso conforme o status da assinatura.

Dependências: starlette (ou fastapi), httpx
"""
from __future__ import annotations

import asyncio
import logging
import time
import weakref
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

logger = logging.getLogger("billing.subscription")


# --------------------------------------------------------------------------- #
# Configuração
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SubscriptionPolicy:
    # Status do faturamento que concedem acesso.
    allowed_statuses: frozenset[str] = frozenset({"active", "trialing"})
    # Por quanto tempo uma resposta do faturamento é reutilizada.
    # Use 0 para consultar o serviço de faturamento em TODA requisição.
    cache_ttl_seconds: float = 60.0
    # Se o faturamento estiver fora do ar, por quanto tempo ainda confiamos
    # no último resultado conhecido (stale). Passado esse prazo, bloqueia.
    max_stale_seconds: float = 900.0
    # False = fail-closed (bloqueia quando não é possível verificar).
    # True  = fail-open (libera). Só use se a política de negócio exigir.
    fail_open: bool = False
    # Rotas que não exigem assinatura ativa (health check, login, portal de
    # pagamento, webhooks, docs...). Sem isso, o cliente inadimplente não
    # conseguiria nem regularizar a assinatura.
    exempt_path_prefixes: tuple[str, ...] = (
        "/health",
        "/auth/login",
        "/billing/portal",
        "/webhooks/",
    )
    max_cache_entries: int = 10_000


# --------------------------------------------------------------------------- #
# Cliente do serviço externo de faturamento
# --------------------------------------------------------------------------- #
class BillingUnavailable(Exception):
    """Serviço de faturamento indisponível ou com resposta inválida."""


class BillingClient:
    def __init__(self, base_url: str, api_token: str, *, client: httpx.AsyncClient | None = None):
        self._client = client or httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {api_token}", "Accept": "application/json"},
            # Timeout curto: o middleware está no caminho crítico de TODA requisição.
            timeout=httpx.Timeout(2.0, connect=1.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )

    async def get_status(self, tenant_id: str) -> str:
        """Retorna o status normalizado da assinatura (ex.: 'active', 'past_due')."""
        try:
            # quote(): evita path traversal / injeção via tenant_id.
            resp = await self._client.get(f"/v1/subscriptions/{quote(tenant_id, safe='')}")
        except httpx.HTTPError as exc:
            raise BillingUnavailable(f"falha de comunicação: {exc.__class__.__name__}") from exc

        if resp.status_code == 404:
            return "none"  # empresa sem assinatura registrada -> não autorizada
        if resp.status_code != 200:
            raise BillingUnavailable(f"status HTTP inesperado: {resp.status_code}")

        try:
            return str(resp.json()["status"]).strip().lower()
        except (ValueError, KeyError, TypeError) as exc:
            raise BillingUnavailable("resposta de faturamento inválida") from exc

    async def aclose(self) -> None:
        await self._client.aclose()


# --------------------------------------------------------------------------- #
# Cache em memória (por processo). Em múltiplas instâncias, considere Redis.
# --------------------------------------------------------------------------- #
@dataclass
class _Entry:
    status: str
    fetched_at: float = field(default_factory=time.monotonic)

    def age(self) -> float:
        return time.monotonic() - self.fetched_at


# --------------------------------------------------------------------------- #
# Middleware
# --------------------------------------------------------------------------- #
class SubscriptionMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        billing: BillingClient,
        policy: SubscriptionPolicy | None = None,
    ) -> None:
        super().__init__(app)
        self._billing = billing
        self._policy = policy or SubscriptionPolicy()
        self._cache: dict[str, _Entry] = {}
        # Um lock por tenant: evita N chamadas simultâneas ao faturamento
        # para a mesma empresa quando o cache expira (thundering herd).
        self._locks: "weakref.WeakValueDictionary[str, asyncio.Lock]" = weakref.WeakValueDictionary()

    # -- ponto de entrada ---------------------------------------------------- #
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Preflight de CORS não carrega credenciais.
        if request.method == "OPTIONS" or self._is_exempt(request.url.path):
            return await call_next(request)

        # IMPORTANTE: o tenant_id deve vir de uma identidade JÁ VALIDADA
        # (claims do JWT / sessão), nunca de header ou parâmetro controlado
        # pelo cliente. Caso contrário, uma empresa poderia se passar por outra.
        tenant_id: str | None = getattr(request.state, "tenant_id", None)
        if not tenant_id:
            return self._deny(401, "UNAUTHENTICATED", "Autenticação necessária.")

        try:
            status = await self._resolve_status(tenant_id)
        except BillingUnavailable as exc:
            logger.error("faturamento indisponível tenant=%s motivo=%s", tenant_id, exc)
            if self._policy.fail_open:
                logger.warning("fail-open ativo: liberando tenant=%s sem verificação", tenant_id)
                return await call_next(request)
            return self._deny(
                503,
                "BILLING_UNAVAILABLE",
                "Não foi possível verificar a assinatura. Tente novamente em instantes.",
                headers={"Retry-After": "30"},
            )

        if status not in self._policy.allowed_statuses:
            logger.info("acesso bloqueado tenant=%s status=%s", tenant_id, status)
            # Mensagem genérica: não vazamos detalhes de faturamento na resposta.
            return self._deny(
                402,
                "SUBSCRIPTION_INACTIVE",
                "A assinatura da empresa não está ativa. Regularize para continuar.",
            )

        request.state.subscription_status = status
        return await call_next(request)

    # -- lógica de verificação ---------------------------------------------- #
    async def _resolve_status(self, tenant_id: str) -> str:
        ttl = self._policy.cache_ttl_seconds

        entry = self._cache.get(tenant_id)
        if entry and entry.age() < ttl:
            return entry.status

        lock = self._locks.get(tenant_id)
        if lock is None:
            lock = self._locks.setdefault(tenant_id, asyncio.Lock())

        async with lock:
            # Double-check: outra corrotina pode ter atualizado enquanto esperávamos.
            entry = self._cache.get(tenant_id)
            if entry and entry.age() < ttl:
                return entry.status

            try:
                status = await self._billing.get_status(tenant_id)
            except BillingUnavailable:
                # Faturamento fora do ar: usa o último resultado conhecido
                # se ainda estiver dentro da janela tolerada.
                if entry and entry.age() < self._policy.max_stale_seconds:
                    logger.warning(
                        "usando status em cache (stale %.0fs) tenant=%s", entry.age(), tenant_id
                    )
                    return entry.status
                raise

            self._store(tenant_id, status)
            return status

    def _store(self, tenant_id: str, status: str) -> None:
        if len(self._cache) >= self._policy.max_cache_entries:
            # Descarta o que já passou da janela máxima de uso; se ainda assim
            # estiver cheio, descarta os mais antigos.
            limit = self._policy.max_stale_seconds
            self._cache = {k: v for k, v in self._cache.items() if v.age() < limit}
            if len(self._cache) >= self._policy.max_cache_entries:
                oldest = sorted(self._cache, key=lambda k: self._cache[k].fetched_at)
                for k in oldest[: len(oldest) // 10 or 1]:
                    self._cache.pop(k, None)
        self._cache[tenant_id] = _Entry(status)

    # -- utilitários --------------------------------------------------------- #
    def _is_exempt(self, path: str) -> bool:
        return any(path.startswith(p) for p in self._policy.exempt_path_prefixes)

    @staticmethod
    def _deny(status_code: int, code: str, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
        return JSONResponse(
            {"error": {"code": code, "message": message}},
            status_code=status_code,
            headers=headers,
        )


# --------------------------------------------------------------------------- #
# Exemplo de uso (FastAPI)
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import os
    from contextlib import asynccontextmanager

    import uvicorn
    from fastapi import FastAPI

    billing = BillingClient(
        base_url=os.environ.get("BILLING_URL", "https://billing.example.com"),
        api_token=os.environ.get("BILLING_TOKEN", "changeme"),
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        await billing.aclose()

    app = FastAPI(lifespan=lifespan)

    # ORDEM: no Starlette, o último middleware adicionado é o mais externo
    # (executa primeiro). A autenticação precisa rodar ANTES da assinatura,
    # pois é ela quem preenche request.state.tenant_id.
    app.add_middleware(SubscriptionMiddleware, billing=billing)
    # app.add_middleware(AuthMiddleware)  # <- valida o JWT e define request.state.tenant_id

    @app.get("/health")
    async def health():
        return {"ok": True}

    @app.get("/relatorios")
    async def relatorios():
        return {"data": "..."}

    uvicorn.run(app, host="0.0.0.0", port=8000)