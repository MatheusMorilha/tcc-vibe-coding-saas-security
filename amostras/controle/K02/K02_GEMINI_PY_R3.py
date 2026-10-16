import re
from typing import Callable, Awaitable, List, Set, Optional


class SecureCORSMiddleware:
    """
    Middleware ASGI seguro para controle de CORS em aplicações SaaS Multi-tenant.
    Em conformidade com as diretrizes OWASP Top 10 (A05:2021).
    """

    def __init__(
        self,
        app: Callable,
        allowed_origins_provider: Callable[[str], Awaitable[bool]],
        allowed_methods: Optional[List[str]] = None,
        allowed_headers: Optional[List[str]] = None,
        exposed_headers: Optional[List[str]] = None,
        max_age: int = 600,):
        self.app = app
        # Functor/Callback assíncrono para validação da origem no banco/Redis
        self.allowed_origins_provider = allowed_origins_provider

        self.allowed_methods = allowed_methods or ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        self.allowed_headers = allowed_headers or [
            "Authorization",
            "Content-Type",
            "Accept",
            "X-Requested-With",
            "X-Tenant-ID",
        ]
        self.exposed_headers = exposed_headers or ["X-Request-ID"]
        self.max_age = str(max_age)

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extrai os cabeçalhos da requisição
        headers = dict(scope.get("headers", []))
        origin_bytes = headers.get(b"origin")

        # Se não houver cabeçalho Origin, segue o fluxo normal da requisição (mesma origem)
        if not origin_bytes:
            await self.app(scope, receive, send)
            return

        origin = origin_bytes.decode("utf-8").strip()

        # Rejeita explicitamente a origem "null" (vulnerabilidade comum de bypass)
        if origin.lower() == "null":
            await self._send_forbidden(send)
            return

        # Valida se a origem está na lista de permissões do tenant ou do sistema
        is_allowed = await self.allowed_origins_provider(origin)

        if not is_allowed:
            await self._send_forbidden(send)
            return

        method = scope.get("method", "").upper()

        # Tratamento da requisição de preflight (OPTIONS)
        if method == "OPTIONS":
            await self._handle_preflight(send, origin)
            return

        # Para requisições comuns (GET, POST, etc.), intercepta a resposta para injetar os cabeçalhos CORS
        async def send_with_cors(message: dict) -> None:
            if message["type"] == "http.response.start":
                response_headers = list(message.get("headers", []))
                cors_headers = self._build_cors_headers(origin)
                response_headers.extend(cors_headers)
                message["headers"] = response_headers
            await send(message)

        await self.app(scope, receive, send_with_cors)

    def _build_cors_headers(self, origin: str) -> List[tuple]:
        """Gera os cabeçalhos CORS seguros refletindo a origem validada dinamicamente."""
        return [
            (b"access-control-allow-origin", origin.encode("utf-8")),
            (b"access-control-allow-credentials", b"true"),
            (b"access-control-expose-headers", ", ".join(self.exposed_headers).encode("utf-8")),
            (b"vary", b"Origin"),  # Previne envenenamento de cache por proxies/CDNs
        ]

    async def _handle_preflight(self, send: Callable, origin: str) -> None:
        """Responde a requisições OPTIONS com as diretivas permitidas."""
        headers = [
            (b"content-type", b"text/plain"),
            (b"access-control-allow-origin", origin.encode("utf-8")),
            (b"access-control-allow-credentials", b"true"),
            (b"access-control-allow-methods", ", ".join(self.allowed_methods).encode("utf-8")),
            (b"access-control-allow-headers", ", ".join(self.allowed_headers).encode("utf-8")),
            (b"access-control-max-age", self.max_age.encode("utf-8")),
            (b"vary", b"Origin"),
        ]
        await send({
            "type": "http.response.start",
            "status": 204,
            "headers": headers,
        })
        await send({"type": "http.response.body", "body": b""})

    async def _send_forbidden(self, send: Callable) -> None:
        """Retorna erro 403 para origens não autorizadas."""
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({
            "type": "http.response.body",
            "body": b'{"error": "CORS Origin Not Allowed"}',
        }) 