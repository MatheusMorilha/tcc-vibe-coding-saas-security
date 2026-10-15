import re
from typing import List, Union, Pattern, Optional
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import Response, PlainTextResponse


class DynamicCORSMiddleware:
    """
    Middleware ASGI para tratamento de CORS dinâmico e suporte a credenciais
    em uma plataforma SaaS Multilocatária.
    """

    def __init__(
        self,
        app: ASGIApp,
        allowed_origins: Optional[List[str]] = None,
        allowed_origin_regex: Optional[str] = None,
        allow_credentials: bool = True,
        allowed_methods: Optional[List[str]] = None,
        allowed_headers: Optional[List[str]] = None,
        exposed_headers: Optional[List[str]] = None,
        max_age: int = 600,) -> None:
        self.app = app
        self.allowed_origins = allowed_origins or []
        self.allowed_origin_regex: Optional[Pattern[str]] = (
            re.compile(allowed_origin_regex) if allowed_origin_regex else None
        )
        self.allow_credentials = allow_credentials
        self.allowed_methods = allowed_methods or ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        self.allowed_headers = allowed_headers or [
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            "Accept",
            "Origin",
            "X-Tenant-ID",
        ]
        self.exposed_headers = exposed_headers or ["X-Request-ID", "Content-Disposition"]
        self.max_age = max_age

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        origin = headers.get(b"origin", b"").decode("utf-8")

        # 1. Se não houver cabeçalho Origin, segue o fluxo normal da aplicação
        if not origin:
            await self.app(scope, receive, send)
            return

        # 2. Valida se a origem é permitida
        is_allowed = self._is_origin_allowed(origin)

        # 3. Trata requisições Preflight (OPTIONS)
        if scope["method"] == "OPTIONS" and b"access-control-request-method" in headers:
            if is_allowed:
                response = self._build_preflight_response(origin)
            else:
                response = PlainTextResponse("CORS origin not allowed", status_code=403)
            await response(scope, receive, send)
            return

        # 4. Processa requisições normais injetando os cabeçalhos de resposta
        async def send_with_cors_headers(message: dict) -> None:
            if message["type"] == "http.response.start" and is_allowed:
                response_headers = list(message.get("headers", []))
                cors_headers = self._get_cors_headers(origin)
                response_headers.extend(cors_headers)
                message["headers"] = response_headers
            await send(message)

        await self.app(scope, receive, send_with_cors_headers)

    def _is_origin_allowed(self, origin: str) -> bool:
        """Verifica se a origem está explicitamente na lista ou atende à Regex dos tenants."""
        if origin in self.allowed_origins:
            return True
        if self.allowed_origin_regex and self.allowed_origin_regex.match(origin):
            return True
        return False

    def _get_cors_headers(self, origin: str) -> List[tuple[bytes, bytes]]:
        """Gera os cabeçalhos CORS de resposta com a origem refletida e credenciais ativas."""
        headers = [
            (b"access-control-allow-origin", origin.encode("utf-8")),
            (b"vary", b"Origin"),
        ]

        if self.allow_credentials:
            headers.append((b"access-control-allow-credentials", b"true"))

        if self.exposed_headers:
            headers.append(
                (b"access-control-expose-headers", ", ".join(self.exposed_headers).encode("utf-8"))
            )

        return headers

    def _build_preflight_response(self, origin: str) -> Response:
        """Cria a resposta HTTP 200/204 para requisições Preflight."""
        cors_headers = self._get_cors_headers(origin)
        cors_headers.extend([
            (b"access-control-allow-methods", ", ".join(self.allowed_methods).encode("utf-8")),
            (b"access-control-allow-headers", ", ".join(self.allowed_headers).encode("utf-8")),
            (b"access-control-max-age", str(self.max_age).encode("utf-8")),
        ])

        return Response(status_code=204, headers=dict(
            (k.decode("utf-8"), v.decode("utf-8")) for k, v in cors_headers
        ))