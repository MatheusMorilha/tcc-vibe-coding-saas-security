"""
Middleware ASGI de verificação de assinatura para plataforma SaaS multilocatária.

Fluxo por requisição:
  1. Obtém o tenant_id do contexto AUTENTICADO (nunca de header/query/body).
  2. Consulta o serviço externo de faturamento (com cache curto + single-flight).
  3. Libera (assinatura ativa) ou bloqueia (402 / 503 / 401 / 403).

Premissas:
  - Este middleware deve rodar DEPOIS da autenticação (ver exemplo de uso no final).
  - O middleware de autenticação grava o tenant_id, extraído de um token já
    validado (assinatura/exp/aud), em scope["state"]["tenant_id"].
    (No Starlette/FastAPI: request.state.tenant_id = "<uuid>").

Dependência: pip install httpx
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

import httpx

logger = logging.getLogger("saas.subscription")

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
TenantResolver = Callable[[Scope], Optional[Any]]

_MAX_BILLING_RESPONSE_BYTES = 16 * 1024  # evita consumo de memória por resposta anômala


# --------------------------------------------------------------------------- #
# Configuração
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SubscriptionConfig:
    billing_base_url: str                      # fixo, vindo de config/ambiente (A10)
    billing_api_key: str = field(repr=False)   # segredo: nunca em repr/log (A02/A09)
    connect_timeout: float = 1.0
    total_timeout: float = 2.5
    cache_ttl_active: float = 60.0             # 0 => consulta a cada requisição
    cache_ttl_inactive: float = 15.0
    stale_grace_seconds: float = 0.0           # 0 => fail-closed estrito (A04)
    max_cache_entries: int = 10_000
    allowed_statuses: frozenset[str] = frozenset({"active", "trialing"})
    # Comparação EXATA (nunca por prefixo), para evitar bypass por path (A01)
    exempt_paths: frozenset[str] = frozenset({"/healthz"})

    def __post_init__(self) -> None:
        if not self.billing_base_url.lower().startswith("https://"):
            raise ValueError("billing_base_url deve usar HTTPS.")
        if not self.billing_api_key:
            raise ValueError("billing_api_key não pode ser vazio.")


class BillingUnavailable(Exception):
    """Serviço de faturamento indisponível ou resposta inválida (fail-closed)."""


@dataclass(slots=True)
class _Entry:
    active: bool
    expires_at: float


class _BoundedCache:
    """Cache LRU com tamanho máximo (evita crescimento ilimitado de memória)."""

    def __init__(self, max_size: int) -> None:
        self._data: OrderedDict[str, _Entry] = OrderedDict()
        self._max = max_size

    def get(self, key: str) -> Optional[_Entry]:
        entry = self._data.get(key)
        if entry is not None:
            self._data.move_to_end(key)
        return entry

    def set(self, key: str, entry: _Entry) -> None:
        self._data[key] = entry
        self._data.move_to_end(key)
        while len(self._data) > self._max:
            self._data.popitem(last=False)


# --------------------------------------------------------------------------- #
# Middleware
# --------------------------------------------------------------------------- #
def _default_tenant_resolver(scope: Scope) -> Optional[Any]:
    return scope.get("state", {}).get("tenant_id")


class SubscriptionMiddleware:
    def __init__(
        self,
        app: Callable[[Scope, Receive, Send], Awaitable[None]],
        config: SubscriptionConfig,
        tenant_resolver: TenantResolver = _default_tenant_resolver,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.app = app
        self.cfg = config
        self._resolve_tenant = tenant_resolver
        self._cache = _BoundedCache(config.max_cache_entries)
        self._inflight: dict[str, asyncio.Future[bool]] = {}
        self._client = client or httpx.AsyncClient(
            base_url=config.billing_base_url,
            headers={
                "Authorization": f"Bearer {config.billing_api_key}",
                "Accept": "application/json",
            },
            timeout=httpx.Timeout(config.total_timeout, connect=config.connect_timeout),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            follow_redirects=False,  # não segue redirecionamentos (SSRF / vazamento de token)
            verify=True,             # validação TLS obrigatória (A02)
            trust_env=False,         # ignora proxies/CA de variáveis de ambiente
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------ #
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):  # lifespan etc.
            await self.app(scope, receive, send)
            return

        if scope["type"] == "http" and scope.get("path") in self.cfg.exempt_paths:
            await self.app(scope, receive, send)
            return

        # 1) Identidade do tenant vem do contexto autenticado, nunca do cliente.
        raw_tenant = self._resolve_tenant(scope)
        if raw_tenant is None:
            await self._deny(scope, send, 401, "authentication_required",
                             "Autenticação necessária.")
            return
        try:
            tenant_id = str(uuid.UUID(str(raw_tenant)))  # normaliza e valida formato
        except (ValueError, AttributeError, TypeError):
            logger.warning("tenant_id inválido no contexto autenticado")
            await self._deny(scope, send, 403, "forbidden", "Acesso negado.")
            return

        # 2) Consulta (com cache/single-flight) e decisão. Fail-closed.
        try:
            active = await self._is_active(tenant_id)
        except BillingUnavailable:
            await self._deny(scope, send, 503, "billing_unavailable",
                             "Não foi possível validar a assinatura. Tente novamente.",
                             extra_headers=[(b"retry-after", b"5")])
            return

        if not active:
            logger.info("acesso bloqueado: assinatura inativa tenant=%s", tenant_id)
            await self._deny(scope, send, 402, "subscription_inactive",
                             "A assinatura da empresa não está ativa.")
            return

        await self.app(scope, receive, send)

    # ------------------------------------------------------------------ #
    async def _is_active(self, tenant_id: str) -> bool:
        now = time.monotonic()
        entry = self._cache.get(tenant_id)
        if entry is not None and now < entry.expires_at:
            return entry.active

        # single-flight: requisições concorrentes do mesmo tenant compartilham 1 chamada
        fut = self._inflight.get(tenant_id)
        if fut is None:
            fut = asyncio.ensure_future(self._fetch_and_store(tenant_id))
            self._inflight[tenant_id] = fut

            def _cleanup(f: asyncio.Future[bool], tid: str = tenant_id) -> None:
                self._inflight.pop(tid, None)
                if not f.cancelled():
                    f.exception()  # marca a exceção como consumida

            fut.add_done_callback(_cleanup)

        try:
            return await asyncio.shield(fut)  # cancelamento de um cliente não derruba a consulta
        except BillingUnavailable:
            # Tolerância opcional e LIMITADA, apenas para quem estava ativo.
            if (
                entry is not None
                and entry.active
                and now < entry.expires_at + self.cfg.stale_grace_seconds
            ):
                logger.warning("faturamento indisponível; usando cache vencido tenant=%s", tenant_id)
                return True
            raise

    async def _fetch_and_store(self, tenant_id: str) -> bool:
        active = await self._fetch_from_billing(tenant_id)
        ttl = self.cfg.cache_ttl_active if active else self.cfg.cache_ttl_inactive
        self._cache.set(tenant_id, _Entry(active, time.monotonic() + ttl))
        return active

    async def _fetch_from_billing(self, tenant_id: str) -> bool:
        # tenant_id é UUID canônico validado: seguro para compor o path (sem injeção).
        path = f"/v1/tenants/{tenant_id}/subscription"
        try:
            async with self._client.stream("GET", path) as resp:
                if resp.status_code == 404:
                    return False  # tenant desconhecido no faturamento => nega
                if resp.status_code != 200:
                    # 401/403 aqui = problema de credencial nossa; 429/5xx = instabilidade
                    logger.error("faturamento respondeu HTTP %s", resp.status_code)
                    raise BillingUnavailable
                body = bytearray()
                async for chunk in resp.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > _MAX_BILLING_RESPONSE_BYTES:
                        logger.error("resposta do faturamento excede o limite")
                        raise BillingUnavailable
        except httpx.HTTPError as exc:  # timeout, conexão, TLS...
            logger.error("falha ao consultar faturamento: %s", type(exc).__name__)
            raise BillingUnavailable from exc

        return self._parse_and_decide(bytes(body), tenant_id)

    def _parse_and_decide(self, body: bytes, tenant_id: str) -> bool:
        """Validação estrita do contrato; qualquer anomalia => fail-closed."""
        try:
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError
            # Integridade: a resposta deve ser sobre o MESMO tenant pedido.
            if str(uuid.UUID(str(data.get("tenant_id")))) != tenant_id:
                logger.error("resposta do faturamento referente a outro tenant")
                raise ValueError
            status = data.get("status")
            if not isinstance(status, str) or not (0 < len(status) <= 32):
                raise ValueError
        except (ValueError, TypeError, AttributeError) as exc:
            logger.error("resposta inválida do faturamento")
            raise BillingUnavailable from exc

        return status.lower() in self.cfg.allowed_statuses

    # ------------------------------------------------------------------ #
    @staticmethod
    async def _deny(
        scope: Scope,
        send: Send,
        status: int,
        code: str,
        message: str,
        extra_headers: Optional[list[tuple[bytes, bytes]]] = None,
    ) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return

        # Mensagens genéricas: não vazam detalhes internos (A05).
        payload = json.dumps({"error": code, "message": message}).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
            (b"cache-control", b"no-store"),
            (b"x-content-type-options", b"nosniff"),
        ] + (extra_headers or [])
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": payload})


# --------------------------------------------------------------------------- #
# Exemplo de uso (FastAPI)
# --------------------------------------------------------------------------- #
# import os
# from fastapi import FastAPI
#
# app = FastAPI()
#
# cfg = SubscriptionConfig(
#     billing_base_url=os.environ["BILLING_BASE_URL"],   # https://billing.exemplo.com
#     billing_api_key=os.environ["BILLING_API_KEY"],     # de um secret manager
# )
#
# # ORDEM IMPORTANTE: no Starlette o ÚLTIMO middleware adicionado é o mais externo.
# # Adicione a assinatura primeiro e a autenticação depois, para que a autenticação
# # execute ANTES e preencha request.state.tenant_id.
# app.add_middleware(SubscriptionMiddleware, config=cfg)
# app.add_middleware(AuthenticationMiddleware)  # seu middleware: valida JWT e
#                                               # define request.state.tenant_id