import re
from typing import Callable, Awaitable, List, Optional
from starlette.types import Scope, Receive, Send
from starlette.responses import Response

class SAASDAtaTenantCORSMiddleware:
    """
    Middleware de CORS seguro para plataforma SaaS Multilocatária.
    Valida a origem dinamicamente contra uma lista permitida (Allowlist/Regex)
    e suporta o envio seguro de credenciais de sessão.
    """
    def __init__(
        self,
        app: Callable,
        allowed_origins: List[str] = None,
        allowed_origin_regex: Optional[str] = None,
        allow_credentials: bool = True,
        max_age: int = 600):
        self.app = app
        self.allowed_origins = set(allowed_origins or [])
        self.allowed_origin_regex = (
            re.compile(allowed_origin_regex) if allowed_origin_regex else None
        )
        self.allow_credentials = allow_credentials
        self.max_age = str(max_age)

        # Métodos e Cabeçalhos permitidos restritos por padrão de segurança
        self.allowed_methods = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        self.allowed_headers = (
            "Authorization, Content-Type, Accept, Origin, "
            "X-Requested-With, X-Tenant-ID"
        )
        self.exposed_headers = "X-Request-ID"

    def _is_origin_allowed(self, origin: str) -> bool:
        """
        Valida se a origem do cliente está autorizada.
        evita vulnerabilidades como correspondência parcial de string (ex: site-evil.com).
        """
        if not origin:
            return False

        if origin in self.allowed_origins:
            return True

        if self.allowed_origin_regex and self.allowed_origin_regex.match(origin):
            return True

        return False

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        origin = headers.get(b"origin", b"").decode("latin1")

        # 1. Trata requisições Preflight (OPTIONS)
        if scope["method"] == "OPTIONS" and origin:
            if self._is_origin_allowed(origin):
                response_headers = {
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Methods": self.allowed_methods,
                    "Access-Control-Allow-Headers": self.allowed_headers,
                    "Access-Control-Expose-Headers": self.exposed_headers,
                    "Access-Control-Max-Age": self.max_age,
                    "Vary": "Origin"
                }

                if self.allow_credentials:
                    response_headers["Access-Control-Allow-Credentials"] = "true"

                # OWASP: Sempre inclua o cabeçalho Vary para evitar envenenamento de Cache HTTP/CDN
                response = Response(status_code=204, headers=response_headers)
                await response(scope, receive, send)
                return
            else:
                # Origem não autorizada em preflight: responde sem os cabeçalhos de CORS
                response = Response(status_code=403, content="Origem Cross-Origin não autorizada.")
                await response(scope, receive, send)
                return

        # 2. Intercepta a resposta de requisições padrão (GET, POST, etc.)
        async def send_with_cors(message):
            if message["type"] == "http.response.start":
                if origin and self._is_origin_allowed(origin):
                    headers_list = list(message.get("headers", []))

                    # Adiciona os cabeçalhos de CORS à resposta final
                    headers_list.append((b"access-control-allow-origin", origin.encode("latin1")))
                    headers_list.append((b"vary", b"Origin"))

                    if self.allow_credentials:
                        headers_list.append((b"access-control-allow-credentials", b"true"))

                    headers_list.append((b"access-control-expose-headers", self.exposed_headers.encode("latin1")))

                    message["headers"] = headers_list

            await send(message)

        await self.app(scope, receive, send_with_cors)