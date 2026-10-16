from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


logger = logging.getLogger(__name__)


class BillingServiceError(Exception):
    """Erro ao consultar o serviço de faturamento."""


class SubscriptionInactive(Exception):
    """Assinatura inexistente, inativa ou não autorizada."""


class BillingClient:
    """
    Cliente do serviço externo de faturamento.

    A URL base é definida exclusivamente por configuração da aplicação.
    Não é aceita nenhuma URL fornecida pelo usuário, evitando SSRF.
    """

    def __init__(
        self,
        base_url: str,
        service_token: str,
        timeout: float = 3.0,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("O serviço de faturamento deve utilizar HTTPS.")

        self._base_url = base_url.rstrip("/")
        self._service_token = service_token

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=1.0,
                read=timeout,
                write=timeout,
                pool=timeout,
            ),
            verify=True,
            follow_redirects=False,
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
            ),
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def subscription_is_active(self, tenant_id: str) -> bool:
        """
        Consulta o estado da assinatura do tenant.

        Importante:
        - tenant_id veio da autenticação, não da requisição do usuário;
        - a URL é construída a partir de uma base confiável;
        - não seguimos redirects;
        - timeout evita prender workers indefinidamente;
        - erros de comunicação são tratados como falha de billing.
        """

        if not tenant_id:
            raise BillingServiceError("Tenant não identificado.")

        # O tenant_id deve ser um identificador interno.
        # Não o utilizamos como URL ou host.
        url = f"{self._base_url}/v1/tenants/{tenant_id}/subscription"

        try:
            response = await self._client.get(
                url,
                headers={
                    "Authorization": f"Bearer {self._service_token}",
                    "Accept": "application/json",
                },
            )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            logger.warning(
                "Falha de comunicação com serviço de faturamento: %s",
                type(exc).__name__,
            )
            raise BillingServiceError(
                "Serviço de faturamento indisponível."
            ) from exc

        if response.status_code == 404:
            # Tenant sem assinatura ativa.
            return False

        if response.status_code in (401, 403):
            # Falha de autenticação/autorização entre serviços.
            # Não devemos interpretar isso como assinatura ativa.
            logger.error(
                "Serviço de faturamento rejeitou a autenticação do serviço."
            )
            raise BillingServiceError(
                "Falha de autenticação no serviço de faturamento."
            )

        if response.status_code >= 500:
            logger.error(
                "Serviço de faturamento retornou HTTP %s.",
                response.status_code,
            )
            raise BillingServiceError(
                "Serviço de faturamento indisponível."
            )

        if response.status_code != 200:
            logger.warning(
                "Resposta inesperada do serviço de faturamento: HTTP %s.",
                response.status_code,
            )
            raise BillingServiceError(
                "Resposta inválida do serviço de faturamento."
            )

        try:
            data: dict[str, Any] = response.json()
        except ValueError as exc:
            raise BillingServiceError(
                "Resposta inválida do serviço de faturamento."
            ) from exc

        # Fail closed:
        # somente o valor booleano True permite acesso.
        return data.get("active") is True


class SubscriptionMiddleware(BaseHTTPMiddleware):
    """
    Middleware que exige assinatura ativa para acessar a aplicação.

    Ordem esperada:

        Request
           |
           v
        Autenticação
           |
           | -> valida token/sessão
           | -> identifica tenant
           v
        SubscriptionMiddleware
           |
           | -> consulta billing
           v
        Endpoint
    """

    def __init__(
        self,
        app,
        billing_client: BillingClient,
    ) -> None:
        super().__init__(app)
        self.billing_client = billing_client

    async def dispatch(
        self,
        request: Request,
        call_next,
    ) -> Response:

        # Rotas públicas podem ser explicitamente excluídas.
        # Nunca use regras baseadas em dados fornecidos pelo cliente
        # para determinar o tenant.
        if request.url.path in {
            "/health",
            "/ready",
        }:
            return await call_next(request)

        tenant_id = getattr(
            request.state,
            "tenant_id",
            None,
        )

        if not isinstance(tenant_id, str) or not tenant_id:
            # Ausência de tenant autenticado não deve resultar
            # em acesso anônimo.
            return JSONResponse(
                {
                    "error": "authentication_required",
                    "message": "Tenant autenticado não identificado.",
                },
                status_code=401,
            )

        try:
            active = await self.billing_client.subscription_is_active(
                tenant_id
            )

        except BillingServiceError:
            # Fail closed.
            #
            # Se não conseguimos verificar a assinatura,
            # não concedemos acesso por padrão.
            return JSONResponse(
                {
                    "error": "billing_unavailable",
                    "message": "Não foi possível validar a assinatura.",
                },
                status_code=503,
            )

        if not active:
            return JSONResponse(
                {
                    "error": "subscription_inactive",
                    "message": "A assinatura da empresa não está ativa.",
                },
                status_code=403,
            )

        return await call_next(request)
