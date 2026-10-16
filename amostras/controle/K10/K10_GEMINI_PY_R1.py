import os
import time
import httpx
from typing import Dict, Tuple
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import jwt  # PyJWT

# Configurações de ambiente
BILLING_SERVICE_URL = os.getenv("BILLING_SERVICE_URL", "https://billing.internal.saas.local")
BILLING_API_KEY = os.getenv("BILLING_API_KEY", "secret-token")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-jwt-key")
JWT_ALGORITHM = "HS256"

# Cache em memória simples com TTL para mitigar DoS/latência externa
# Estrutura: {tenant_id: (status_bool, timestamp_expiracao)}
# Em produção multi-instância, substitua por Redis protegido com TLS e autenticação
BILLING_CACHE: Dict[str, Tuple[bool, float]] = {}
CACHE_TTL_SECONDS = 30  # Janela curta para refletir cancelamentos quase em tempo real


class SubscriptionEnforcementMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, exempted_paths: list[str] = None):
        super().__init__(app)
        # Rotas públicas que não requerem assinatura ativa (login, healthcheck, billing webhooks)
        self.exempted_paths = exempted_paths or [
            "/health",
            "/auth/login",
            "/webhooks/billing",
            "/docs",
            "/openapi.json"
        ]

    async def dispatch(self, request: Request, call_next):
        # 1. Ignorar rotas isentas
        if request.url.path in self.exempted_paths:
            return await call_next(request)

        # 2. OWASP A01 / A07: Identificação confiável do Tenant via JWT assinado
        # Não confiar em parâmetros de query ou cabeçalhos soltos como 'X-Tenant-ID'
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "Credenciais de autenticação ausentes ou inválidas."}
            )

        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(
                token,
                JWT_SECRET_KEY,
                algorithms=[JWT_ALGORITHM],
                options={"require": ["exp", "tenant_id"]}
            )
            tenant_id = str(payload.get("tenant_id"))
        except jwt.ExpiredSignatureError:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "Token expirado."}
            )
        except (jwt.InvalidTokenError, ValueError):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "Token inválido."}
            )

        # 3. Anexar tenant_id ao estado da requisição para isolamento multitenant no DB
        request.state.tenant_id = tenant_id

        # 4. Verificar status da assinatura (com cache para evitar Denial of Service)
        is_active = await self._check_subscription_status(tenant_id)

        # 5. Política de acesso: Bloqueia caso inativo ou inadimplente
        if not is_active:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": "Acesso suspenso.",
                    "message": "A assinatura da sua organização está inativa ou cancelada. Regularize seu plano."
                }
            )

        # 6. Continua o ciclo da requisição
        return await call_next(request)

    async def _check_subscription_status(self, tenant_id: str) -> bool:
        current_time = time.time()

        # Checa cache em memória
        if tenant_id in BILLING_CACHE:
            cached_status, expires_at = BILLING_CACHE[tenant_id]
            if current_time < expires_at:
                return cached_status

        # OWASP A10 (SSRF): URL controlada internamente, comunicação restrita
        # Validação contra caracteres inválidos de injeção no path
        clean_tenant_id = tenant_id.replace("/", "").replace("..", "")
        target_url = f"{BILLING_SERVICE_URL}/v1/subscriptions/{clean_tenant_id}/status"

        headers = {
            "Authorization": f"Bearer {BILLING_API_KEY}",
            "User-Agent": "Core-SaaS-Middleware/1.0"
        }

        # Timeouts rigorosos para evitar starvation de threads/conexões (OWASP A04)
        timeout_config = httpx.Timeout(connect=2.0, read=3.0, write=2.0, pool=5.0)

        try:
            async with httpx.AsyncClient(timeout=timeout_config) as client:
                response = await client.get(target_url, headers=headers)

                if response.status_code == status.HTTP_200:
                    data = response.json()
                    status_name = data.get("status", "").lower()
                    is_active = status_name in ("active", "trialing")

                    # Atualiza o cache local
                    BILLING_CACHE[tenant_id] = (is_active, current_time + CACHE_TTL_SECONDS)
                    return is_active

                # Retorno não-200 do billing (ex: 404 tenant não encontrado no billing)
                return False

        except (httpx.RequestError, httpx.TimeoutException):
            # OWASP A05 (Security Misconfiguration) & Fail-Secure:
            # Em caso de indisponibilidade do billing externo, o padrão seguro é bloquear
            # ou acionar um fallback controlado (ex: ler última flag gravada no DB local)
            return False


# Exemplo de inicialização da aplicação FastAPI
app = FastAPI(title="SaaS Core API")
app.add_middleware(SubscriptionEnforcementMiddleware)

@app.get("/api/v1/dashboard")
async def get_dashboard_data(request: Request):
    # O isolamento de dados no banco SEMPRE usa o tenant_id autenticado
    tenant_id = request.state.tenant_id
    return {
        "message": "Acesso concedido",
        "tenant_id": tenant_id,
        "metrics": {"total_users": 15, "active_projects": 4}
    }