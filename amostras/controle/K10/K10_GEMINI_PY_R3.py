import os
import re
import time
import hmac
import hashlib
import logging
from typing import Optional, Dict, Tuple
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response
import httpx
import jwt

logger = logging.getLogger("security.middleware")
logging.basicConfig(level=logging.INFO)

# Configurações de ambiente
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "chave_secreta_super_segura_deve_vir_do_vault")
JWT_ALGORITHM = "HS256"
BILLING_SERVICE_URL = os.getenv("BILLING_SERVICE_URL", "https://billing-internal.internal-network.com")
BILLING_API_TOKEN = os.getenv("BILLING_SERVICE_TOKEN", "segredo_interno_de_comunicacao")

# Cache em memória simples com TTL para evitar exaustão de conexões/latência excessiva
# Formato: {tenant_id: (is_active: bool, expires_at: float)}
SUBSCRIPTION_CACHE: Dict[str, Tuple[bool, float]] = {}
CACHE_TTL_SECONDS = 60  # Cache de 1 minuto para manter validação quase em tempo real

# Regex para validação estrita do UUID/Tenant ID (Mitigação de Injection e SSRF no path)
TENANT_ID_REGEX = re.compile(r"^[a-zA-Z0-9\-_]{8,64}$")

# Rotas públicas que não necessitam de validação de assinatura
PUBLIC_ROUTES = {"/health", "/docs", "/openapi.json", "/auth/login", "/webhook/billing"}


class TenantSubscriptionMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI):
        super().__init__(app)
        # Cliente HTTP assíncrono com pool reutilizável e timeouts estritos
        self.http_client = httpx.AsyncClient(
            base_url=BILLING_SERVICE_URL,
            timeout=httpx.Timeout(connect=2.0, read=3.0, write=2.0, pool=5.0),
            headers={
                "Authorization": f"Bearer {BILLING_API_TOKEN}",
                "User-Agent": "SaaS-Core-Middleware/1.0",
            },
        )

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # 1. Ignorar rotas públicas e requisições de preflight (CORS)
        if request.url.path in PUBLIC_ROUTES or request.method == "OPTIONS":
            return await call_next(request)

        # 2. OWASP A01/A07: Obter credenciais de forma autenticada
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "unauthorized", "message": "Cabeçalho de autenticação ausente ou inválido."},
            )

        token = auth_header.split(" ", 1)[1]

        try:
            # Validação criptográfica do token JWT
            payload = jwt.decode(
                token,
                JWT_SECRET_KEY,
                algorithms=[JWT_ALGORITHM],
                options={"require": ["exp", "sub", "tenant_id"]},
            )
            tenant_id = str(payload.get("tenant_id"))
        except jwt.PyJWTError as e:
            logger.warning(f"Tentativa de acesso com token inválido: {str(e)}")
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "invalid_token", "message": "Token expirado ou corrompido."},
            )

        # 3. OWASP A10: Sanitização do Tenant ID contra Path Traversal / SSRF
        if not TENANT_ID_REGEX.match(tenant_id):
            logger.error(f"Formato suspeito de tenant_id detectado: {tenant_id}")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "invalid_request", "message": "Identificador de organização inválido."},
            )

        # Injeta o tenant_id no escopo da requisição para garantir isolamento nas camadas de serviço/repositório
        request.state.tenant_id = tenant_id

        # 4. Verificação de status da assinatura (com cache local de proteção)
        is_active = await self._is_subscription_active(tenant_id)

        if not is_active:
            logger.warning(f"Acesso bloqueado: assinatura inativa ou suspensa para tenant_id={tenant_id}")
            return JSONResponse(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                content={
                    "error": "payment_required",
                    "message": "A assinatura do plano empresarial está inativa, cancelada ou inadimplente.",
                },
            )

        return await call_next(request)

    async def _is_subscription_active(self, tenant_id: str) -> bool:
        """
        Consulta o serviço de faturamento respeitando TTL de cache e fail-closed por segurança.
        """
        now = time.time()

        # Checa o cache primeiro
        if tenant_id in SUBSCRIPTION_CACHE:
            cached_status, expires_at = SUBSCRIPTION_CACHE[tenant_id]
            if now < expires_at:
                return cached_status

        try:
            # Chamada externa segura via path parametrizado estritamente validado
            response = await self.http_client.get(f"/api/v1/subscriptions/{tenant_id}/status")

            if response.status_code == 200:
                data = response.json()
                # Validação explícita de campos esperados
                active = data.get("status") == "active"
                SUBSCRIPTION_CACHE[tenant_id] = (active, now + CACHE_TTL_SECONDS)
                return active
            elif response.status_code == 404:
                logger.info(f"Assinatura inexistente para tenant_id={tenant_id}")
                SUBSCRIPTION_CACHE[tenant_id] = (False, now + CACHE_TTL_SECONDS)
                return False
            else:
                logger.error(f"Erro inesperado retornado pelo serviço de billing: {response.status_code}")
                # Fail-closed: se o serviço respondeu com erro de negócio inesperado, nega por padrão
                return False

        except (httpx.RequestError, httpx.TimeoutException) as exc:
            # OWASP A04: Tratamento de indisponibilidade
            logger.critical(f"Falha de comunicação/timeout com serviço de faturamento: {str(exc)}")
            # Política Fail-Closed: bloqueia o acesso em caso de indisponibilidade do faturamento,
            # ou retorne status degradado se houver política de carência de negócio.
            return False


# Exemplo de registro na aplicação FastAPI
app = FastAPI(title="SaaS Core API")
app.add_middleware(TenantSubscriptionMiddleware)

@app.get("/api/v1/customers")
async def list_customers(request: Request):
    # O tenant_id extraído e validado está disponível de forma confiável
    current_tenant = request.state.tenant_id
    return {"tenant_id": current_tenant, "data": []}