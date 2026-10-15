from typing import Callable, Set, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, PlainTextResponse


class DynamicTenantCORSMiddleware(BaseHTTPMiddleware):
    """
    Middleware ASGI para gerenciamento dinâmico de CORS em ambiente SaaS Multi-tenant.
    Permite requisições enviando credenciais (cookies de sessão, headers de auth)
    apenas para origens autorizadas (domínios e subdomínios de clientes válidos).
    """

    def __init__(
        self,
        app,
        allowed_origins_static: Optional[Set[str]] = None,
        allowed_methods: Optional[list[str]] = None,
        allowed_headers: Optional[list[str]] = None,
        max_age: int = 600,):
        super().__init__(app)
        # Origens estáticas padrão (ex: painel interno da plataforma SaaS)
        self.allowed_origins_static = allowed_origins_static or {
            "https://app.minhaplataformasaas.com",
            "https://admin.minhaplataformasaas.com",
        }
        self.allowed_methods = ", ".join(
            allowed_methods or ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        )
        self.allowed_headers = ", ".join(
            allowed_headers or [
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Accept",
                "Origin",
                "X-Tenant-ID",
            ]
        )
        self.max_age = str(max_age)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        origin = request.headers.get("origin")

        # Se não houver cabeçalho 'Origin' (requisições server-to-server ou same-origin),
        # o fluxo segue normalmente sem cabeçalhos CORS.
        if not origin:
            return await call_next(request)

        # Valida se a origem remetente é permitida
        is_allowed = await self._is_origin_allowed(request, origin)

        # Tratamento para requisições Preflight (HTTP OPTIONS)
        if request.method == "OPTIONS" and "access-control-request-method" in request.headers:
            if not is_allowed:
                return PlainTextResponse("CORS origin not allowed", status_code=403)

            response = Response(status_code=200)
            self._apply_cors_headers(response, origin)
            return response

        # Requisições normais (GET, POST, etc.)
        if not is_allowed:
            # Caso a origem não seja válida, prossegue sem injetar cabeçalhos CORS.
            # O navegador bloqueará a leitura da resposta no cliente.
            return await call_next(request)

        response = await call_next(request)
        self._apply_cors_headers(response, origin)
        return response

    async def _is_origin_allowed(self, request: Request, origin: str) -> bool:
        """
        Valida a origem contra a lista estática ou dinamicamente no banco de dados.
        """
        # 1. Verifica origens estáticas do próprio SaaS
        if origin in self.allowed_origins_static:
            return True

        # 2. Validação Dinâmica de Tenant (Empresa Cliente)
        # Em ambiente de produção, utilize cache (ex: Redis) para evitar consultas
        # constantes ao banco de dados em cada requisição Preflight/CORS.
        tenant_domain = origin.replace("https://", "").replace("http://", "").split(":")[0]

        return await self._validate_tenant_domain_in_db(request, tenant_domain)

    async def _validate_tenant_domain_in_db(self, request: Request, domain: str) -> bool:
        """
        Simulação da consulta ao banco de dados / cache de tenants ativas.
        """
        # Exemplo prático de verificação:
        # db = request.state.db
        # tenant = await db.tenants.find_first(domain=domain, status="active")
        # return tenant is not None

        # Exemplo simulado de domínios cadastrados:
        known_active_tenants = {"empresaA.com", "app.clienteB.com.br"}
        return domain in known_active_tenants

    def _apply_cors_headers(self, response: Response, origin: str) -> None:
        """
        Aplica os cabeçalhos HTTP estritamente necessários para permitir CORS com credenciais.
        """
        # Ecoa a origem exata para satisfazer a exigência de Allow-Credentials
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = self.allowed_methods
        response.headers["Access-Control-Allow-Headers"] = self.allowed_headers
        response.headers["Access-Control-Max-Age"] = self.max_age

        # Garante que intermediários (CDNs/Proxies) façam cache separado por origem
        response.headers["Vary"] = "Origin"