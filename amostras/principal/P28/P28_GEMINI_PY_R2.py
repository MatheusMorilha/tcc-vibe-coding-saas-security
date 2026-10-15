import hmac
import hashlib
import logging
from typing import Callable, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response, status, Header, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import httpx
import redis.asyncio as redis

logger = logging.getLogger("tenant_subscription_middleware")

# Configurações de Ambiente
REDIS_URL = "redis://localhost:6379/0"
BILLING_SERVICE_URL = "https://api.billing-service.com/v1/tenants"
BILLING_API_KEY = "secret_billing_api_key_here"
WEBHOOK_SECRET = "webhook_signing_secret_here"
CACHE_TTL_SECONDS = 3600  # 1 hora
FAIL_OPEN_ON_OUTAGE = False  # Troque para True se preferir não bloquear clientes durante outages


class TenantSubscriptionMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI, redis_client: redis.Redis, http_client: httpx.AsyncClient):
        super().__init__(app)
        self.redis = redis_client
        self.http_client = http_client

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # 1. Ignorar rotas públicas
        public_paths = {"/health", "/docs", "/openapi.json", "/api/v1/webhooks/billing"}
        if request.url.path in public_paths:
            return await call_next(request)

        # 2. Extrair o tenant_id (Header ou context state)
        tenant_id = request.headers.get("X-Tenant-ID")
        if not tenant_id:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Header X-Tenant-ID ausente na requisição."}
            )

        # 3. Consultar status com cache / fallback
        is_active = await self._check_subscription_status(tenant_id)

        # 4. Bloquear acesso se inativo
        if not is_active:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": "subscription_inactive",
                    "detail": "Acesso negado. A assinatura do tenant está inativa ou suspensa."
                }
            )

        return await call_next(request)

    async def _check_subscription_status(self, tenant_id: str) -> bool:
        cache_key = f"tenant_status:{tenant_id}"

        # Tenta obter do Redis
        try:
            cached_status = await self.redis.get(cache_key)
            if cached_status is not None:
                return cached_status.decode("utf-8") == "active"
        except Exception as exc:
            logger.error(f"Falha de leitura no Redis para o tenant {tenant_id}: {exc}")

        # Cache Miss ou erro do Redis -> Fallback para API de billing
        return await self._fetch_status_from_billing_service(tenant_id, cache_key)

    async def _fetch_status_from_billing_service(self, tenant_id: str, cache_key: str) -> bool:
        url = f"{BILLING_SERVICE_URL}/{tenant_id}/subscription"

        try:
            response = await self.http_client.get(url)

            if response.status_code == 200:
                data = response.json()
                is_active = data.get("status") == "active"
                status_str = "active" if is_active else "inactive"

                # Escreve no Redis sem travar a requisição em caso de falha
                try:
                    await self.redis.setex(cache_key, CACHE_TTL_SECONDS, status_str)
                except Exception as cache_exc:
                    logger.warning(f"Falha ao gravar no Redis para {tenant_id}: {cache_exc}")

                return is_active

            logger.warning(f"Billing service respondeu status {response.status_code} para tenant {tenant_id}")
            return False

        except (httpx.RequestError, httpx.TimeoutException) as exc:
            logger.error(f"Erro de comunicação com serviço de faturamento: {exc}")
            # Política de degradação graciosa: Fail-Open vs Fail-Closed
            return FAIL_OPEN_ON_OUTAGE


# --- Aplicação e Lifespan Context Manager ---

redis_client = redis.from_url(REDIS_URL)
http_client = httpx.AsyncClient(
    timeout=3.0,
    headers={"Authorization": f"Bearer {BILLING_API_KEY}"}
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Setup
    yield
    # Cleanup gracioso no encerramento da API
    await redis_client.close()
    await http_client.aclose()


app = FastAPI(title="SaaS Multi-tenant API", lifespan=lifespan)

# Registra o middleware com as instâncias reutilizáveis
app.add_middleware(
    TenantSubscriptionMiddleware,
    redis_client=redis_client,
    http_client=http_client
)


# --- Endpoint Protegido de Webhook ---

def verify_webhook_signature(payload_bytes: bytes, signature_header: Optional[str]) -> bool:
    """Valida se o webhook realmente foi enviado pelo gateway autorizado."""
    if not signature_header:
        return False

    expected_signature = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected_signature, signature_header)


@app.post("/api/v1/webhooks/billing")
async def handle_billing_webhook(
    request: Request,
    x_signature: Optional[str] = Header(None, alias="X-Signature")):
    body = await request.body()

    # 1. Validação da Assinatura HMAC
    if not verify_webhook_signature(body, x_signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Assinatura de Webhook inválida."
        )

    payload = await request.json()
    tenant_id = payload.get("tenant_id")
    new_status = payload.get("status")

    if tenant_id and new_status:
        cache_key = f"tenant_status:{tenant_id}"
        val = "active" if new_status == "active" else "inactive"
        await redis_client.setex(cache_key, CACHE_TTL_SECONDS, val)
        logger.info(f"Cache de assinatura atualizado via Webhook para o tenant: {tenant_id} -> {val}")

    return {"status": "success"}


@app.get("/api/v1/dashboard")
async def get_dashboard_data():
    return {"message": "Dados do dashboard carregados com sucesso!"}