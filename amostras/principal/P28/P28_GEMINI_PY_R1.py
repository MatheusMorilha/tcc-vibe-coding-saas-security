import time
import logging
from typing import Optional
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import httpx
import redis.asyncio as redis

logger = logging.getLogger("tenant_billing_middleware")

# Configuração do Redis e do Serviço de Billing
REDIS_URL = "redis://localhost:6379/0"
BILLING_SERVICE_URL = "https://api.billing-service.internal/v1/subscriptions"
BILLING_API_TIMEOUT = 2.0  # segundos
CACHE_TTL_SECONDS = 300   # 5 minutos de cache para evitar sobrecarga na API

redis_client = redis.from_url(REDIS_URL, decode_responses=True)


class TenantSubscriptionMiddleware(BaseHTTPMiddleware):
    """
    Middleware responsável por interceptar as requisições, identificar o tenant,
    verificar o status da assinatura (com cache) e liberar/bloquear o acesso.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # 1. Ignorar rotas públicas (health check, documentação, auth, webhooks)
        if request.url.path in ["/health", "/docs", "/openapi.json", "/api/v1/auth/login"]:
            return await call_next(request)

        # 2. Extrair o ID do Tenant da requisição
        # (pode vir de subdomínio, cabeçalho X-Tenant-ID ou token JWT decodificado)
        tenant_id = request.headers.get("X-Tenant-ID")

        if not tenant_id:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Cabeçalho 'X-Tenant-ID' é obrigatório."}
            )

        # 3. Verificar status da assinatura
        is_active = await self._is_subscription_active(tenant_id)

        # 4. Bloquear acesso caso a assinatura não esteja ativa
        if not is_active:
            return JSONResponse(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                content={
                    "error": "Assinatura inativa ou suspensa.",
                    "code": "SUBSCRIPTION_INACTIVE",
                    "message": "Acesse o painel financeiro para regularizar sua assinatura."
                }
            )

        # 5. Injetar o tenant_id no estado da requisição para uso nas rotas/controllers
        request.state.tenant_id = tenant_id

        # 6. Prosseguir com a requisição
        return await call_next(request)

    async def _is_subscription_active(self, tenant_id: str) -> bool:
        cache_key = f"tenant:{tenant_id}:subscription_status"

        # Tenta recuperar o status do Cache (Redis)
        try:
            cached_status = await redis_client.get(cache_key)
            if cached_status is not None:
                return cached_status == "active"
        except Exception as e:
            logger.error(f"Erro ao acessar Redis: {str(e)}")

        # Caso não esteja em cache, consulta o serviço externo de billing
        status_from_api = await self._fetch_status_from_billing_service(tenant_id)

        if status_from_api is not None:
            # Salva o resultado no Redis com TTL curto
            try:
                await redis_client.set(cache_key, status_from_api, ex=CACHE_TTL_SECONDS)
            except Exception as e:
                logger.error(f"Erro ao salvar no Redis: {str(e)}")

            return status_from_api == "active"

        # Estratégia Fail-Open: Se a API externa falhar/estiver indisponível,
        # liberamos a requisição temporariamente para evitar downtime total do SaaS.
        logger.warning(f"Fallback acionado para o tenant {tenant_id}. Liberando acesso temporário.")
        return True

    async def _fetch_status_from_billing_service(self, tenant_id: str) -> Optional[str]:
        headers = {"X-Internal-Secret": "sua_chave_interna_aqui"}

        try:
            async with httpx.AsyncClient(timeout=BILLING_API_TIMEOUT) as client:
                response = await client.get(
                    f"{BILLING_SERVICE_URL}/{tenant_id}",
                    headers=headers
                )

                if response.status_code == 200:
                    data = response.json()
                    return data.get("status")  # Ex: "active", "canceled", "past_due"

                logger.warning(
                    f"Serviço de billing retornou HTTP {response.status_code} para tenant {tenant_id}"
                )
                return "inactive"

        except (httpx.TimeoutException, httpx.RequestError) as exc:
            logger.error(f"Falha ao comunicar com serviço externo de billing: {exc}")
            return None  # Retorna None para acionar a estratégia de Fail-Open