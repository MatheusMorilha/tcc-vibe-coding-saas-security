import logging
from typing import Callable
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
import httpx
import redis.asyncio as redis

logger = logging.getLogger(__name__)

# Configurações de serviços e cache
BILLING_SERVICE_URL = "https://billing.internal/v1/subscriptions"
CACHE_TTL_SECONDS = 300  # 5 minutos de cache para evitar sobrecarga no billing

# Clientes de Redis e HTTP (compartilhados na aplicação)
redis_client = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)
httpx_client = httpx.AsyncClient(timeout=3.0)


async def check_subscription_status(tenant_id: str) -> bool:
    """Verifica se a assinatura está ativa, usando cache em memória (Redis)

    com fallback resiliente para o serviço externo de faturamento.
    """
    cache_key = f"tenant:{tenant_id}:subscription_active"

    # 1. Consulta o Cache em memória
    try:
        cached_status = await redis_client.get(cache_key)
        if cached_status is not None:
            return cached_status == "true"
    except Exception as err:
        logger.warning(f"Falha ao acessar o Redis: {err}")

    # 2. Cache miss: Consulta o Serviço Externo de Faturamento
    try:
        url = f"{BILLING_SERVICE_URL}/{tenant_id}"
        response = await httpx_client.get(url, headers={"X-Internal-Service": "api-gateway"})

        if response.status_code == 200:
            data = response.json()
            is_active: bool = data.get("status") == "ACTIVE"

            # Atualiza o cache de forma não-bloqueante
            try:
                await redis_client.setex(cache_key, CACHE_TTL_SECONDS, "true" if is_active else "false")
            except Exception as err:
                logger.warning(f"Falha ao atualizar cache no Redis: {err}")

            return is_active

        logger.error(f"Serviço de faturamento retornou status {response.status_code} para tenant {tenant_id}")
        return False

    except (httpx.RequestError, httpx.TimeoutException) as err:
        logger.error(f"Erro de comunicação com serviço de faturamento: {err}")
        # Estratégia de resiliência: em caso de queda do billing service, decide-se se
        # bloqueia por padrão ou libera temporariamente dependendo do SLA de negócio.
        return False


async def tenancy_and_billing_middleware(request: Request, call_next: Callable) -> Response:
    """Middleware responsável por extrair a identificação do tenant e validar a assinatura."""
    # Rotas isentas de verificação de tenancy/assinatura
    public_paths = ["/health", "/docs", "/openapi.json", "/auth/login"]
    if request.url.path in public_paths:
        return await call_next(request)

    # Extração do ID da empresa (Tenant ID) a partir do cabeçalho HTTP
    tenant_id = request.headers.get("X-Tenant-ID")

    if not tenant_id:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Cabeçalho 'X-Tenant-ID' é obrigatório."},
        )

    # Validação do status da assinatura da empresa
    is_subscription_active = await check_subscription_status(tenant_id)

    if not is_subscription_active:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "code": "SUBSCRIPTION_INACTIVE",
                "message": "Acesso bloqueado. A assinatura da empresa está inativa ou pendente de pagamento.",
            },
        )

    # Injeta o tenant_id no estado da requisição para acesso nos controllers/endpoints
    request.state.tenant_id = tenant_id

    response = await call_next(request)
    return response


# Exemplo de integração no App FastAPI
app = FastAPI(title="SaaS Multi-tenant Platform")
app.middleware("http")(tenancy_and_billing_middleware)


@app.get("/api/v1/dashboard")
async def get_dashboard(request: Request):
    # Recupera o tenant_id injetado pelo middleware
    tenant_id = request.state.tenant_id
    return {"message": f"Dados do dashboard para a empresa {tenant_id}"}