import os
import re
import hmac
import hashlib
import logging
from typing import Optional, Set
import httpx
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.status import (
    HTTP_401_UNAUTHORIZED,
    HTTP_402_PAYMENT_REQUIRED,
    HTTP_503_SERVICE_UNAVAILABLE,
)
import jwt  # PyJWT

# Configuração de Logs Seguros
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SubscriptionMiddleware")

# Configurações de Ambiente
BILLING_SERVICE_BASE_URL = os.getenv("BILLING_SERVICE_URL", "https://billing.internal.saas/api/v1")
BILLING_API_KEY = os.getenv("BILLING_INTERNAL_API_KEY", "")
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "change-me-in-production")
JWT_ALGORITHM = "HS256"

# Padrão estrito de Tenant ID (evita injeção e caracteres maliciosos na URL externa - OWASP SSRF / Path Traversal)
TENANT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")

# Rotas que não exigem verificação de plano (Health checks, login, webhooks)
EXEMPT_PATHS: Set[str] = {
    "/health",
    "/metrics",
    "/api/v1/auth/login",
    "/api/v1/billing/webhook",  # Recebimento de eventos do próprio gateway
}

# Cache simplificado em memória com TTL (Em produção com réplicas, utilizar Redis)
import time
CACHE_TTL_SECONDS = 60
_subscription_cache: dict[str, tuple[bool, float]] = {}


class SubscriptionEnforcementMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        # Timeout estrito para proteger contra esgotamento de conexões (OWASP Denial of Service)
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(2.0, connect=1.0),
            headers={
                "Authorization": f"Bearer {BILLING_API_KEY}",
                "User-Agent": "SaaS-Core-Middleware/1.0",
            },
        )

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # 1. Ignorar rotas públicas e webhooks
        if request.url.path in EXEMPT_PATHS or request.method == "OPTIONS":
            return await call_next(request)

        # 2. OWASP A01: Quebra de Controle de Acesso (Broken Access Control)
        # O Tenant ID é extraído de uma fonte confiável (JWT validado), nunca de cabeçalhos livres
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"error": "Credenciais de autenticação não fornecidas ou inválidas."},
            )

        token = auth_header.split(" ")[1]
        tenant_id = self._extract_and_validate_tenant(token)

        if not tenant_id:
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"error": "Sessão inválida ou tenant não identificado."},
            )

        # 3. Injetar o tenant_id no estado da requisição para isolamento em queries subsequentes
        request.state.tenant_id = tenant_id

        # 4. Checar status da assinatura no serviço externo
        try:
            is_active = await self._is_subscription_active(tenant_id)
        except httpx.RequestError as exc:
            logger.error(
                "Falha de comunicação com o serviço de faturamento para o tenant %s: %s",
                tenant_id,
                str(exc),
            )
            # OWASP A05: Falha segura - não expor mensagens de erro internas ou stack trace
            return JSONResponse(
                status_code=HTTP_503_SERVICE_UNAVAILABLE,
                content={"error": "Serviço de validação temporariamente indisponível. Tente novamente."},
            )

        # 5. Bloqueio caso a assinatura esteja inativa/inadimplente
        if not is_active:
            logger.warning("Acesso bloqueado: Assinatura suspensa ou cancelada para o tenant: %s", tenant_id)
            return JSONResponse(
                status_code=HTTP_402_PAYMENT_REQUIRED,
                content={
                    "error": "Acesso bloqueado: Assinatura da empresa inativa ou pendente de pagamento.",
                    "code": "SUBSCRIPTION_INACTIVE",
                },
            )

        return await call_next(request)

    def _extract_and_validate_tenant(self, token: str) -> Optional[str]:
        """Valida o JWT e extrai o tenant_id de forma segura."""
        try:
            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALGORITHM],
                options={"require": ["exp", "sub", "tenant_id"]},
            )
            tenant_id = str(payload.get("tenant_id"))

            # Validação sintática para proteção contra SSRF e Injeções
            if not TENANT_ID_PATTERN.match(tenant_id):
                logger.error("Tentativa de injeção no tenant_id detectada: %s", tenant_id)
                return None

            return tenant_id
        except (jwt.PyJWTError, ValueError) as err:
            logger.warning("Falha na validação do token JWT: %s", str(err))
            return None

    async def _is_subscription_active(self, tenant_id: str) -> bool:
        """Verifica se a assinatura está ativa, usando cache em memória com TTL."""
        now = time.time()

        # Consulta Cache
        if tenant_id in _subscription_cache:
            status, timestamp = _subscription_cache[tenant_id]
            if now - timestamp < CACHE_TTL_SECONDS:
                return status

        # Consulta externa ao serviço de faturamento (OWASP A10: URL estática + parâmetro validado)
        endpoint = f"{BILLING_SERVICE_BASE_URL}/subscriptions/{tenant_id}/status"
        response = await self.http_client.get(endpoint)

        if response.status_code == 200:
            data = response.json()
            is_active = data.get("status") in {"active", "trialing"}
            _subscription_cache[tenant_id] = (is_active, now)
            return is_active
        elif response.status_code == 404:
            # Tenant não possui cadastro de faturamento
            _subscription_cache[tenant_id] = (False, now)
            return False
        else:
            raise httpx.RequestError(f"Billing service returned unexpected status: {response.status_code}")

from fastapi import FastAPI, Request

app = FastAPI(title="SaaS Core API")

# Registra o middleware
app.add_middleware(SubscriptionEnforcementMiddleware)

@app.get("/api/v1/dashboard")
async def get_dashboard_data(request: Request):
    # O tenant_id já foi autenticado e validado pelo middleware
    tenant_id = request.state.tenant_id
    return {"message": "Acesso permitido", "tenant_id": tenant_id}