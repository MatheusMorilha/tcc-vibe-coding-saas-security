import re
from typing import Callable, List, Optional
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

class SecureMultiTenantCORSMiddleware:
    """
    Middleware de CORS multilocatário seguro para aplicações ASGI (FastAPI / Starlette).
    Aplica boas práticas do OWASP Top 10 para prevenção de A01:2021 (Broken Access Control)
    e A05:2021 (Security Misconfiguration).
    """

    def __init__(
        self,
        app: ASGIApp,
        allowed_domain_pattern: str = r"^https://([a-zA-Z0-9-]+\.)?minhaplataforma\.com\.br$",
        allowed_explicit_origins: Optional[List[str]] = None,
        allowed_methods: Optional[List[str]] = None,
        allowed_headers: Optional[List[str]] = None,
        max_age: int = 600,):
        self.app = app
        # Expressão regular para validar domínios de clientes/locatários e subdomínios confiáveis
        self.allowed_origin_regex = re.compile(allowed_domain_pattern)
        # Lista explícita de origens permitidas (ex: portal principal, ambiente de dev/staging)
        self.allowed_explicit_origins = set(allowed_explicit_origins or [])
        self.allowed_methods = allowed_methods or ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        self.allowed_headers = allowed_headers or [
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            "Accept",
            "X-Tenant-ID",
        ]
        self.max_age = max_age

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        origin = headers.get("origin")

        # Se não houver cabeçalho 'Origin', requisição é do mesmo domínio ou não-navegador
        if not origin:
            await self.app(scope, receive, send)
            return

        # Validação estrita da origem informada
        is_allowed = self._is_origin_allowed(origin)

        # Trata requisição Preflight (OPTIONS)
        if scope["method"] == "OPTIONS" and headers.get("access-control-request-method"):
            if is_allowed:
                response_headers = self._get_preflight_headers(origin)
                await self._send_response(send, status=200, headers=response_headers)
            else:
                # OWASP: Rejeita explicitamente origens não autorizadas
                await self._send_response(send, status=403, headers=[(b"content-type", b"text/plain")])
            return

        # Requisição padrão (GET, POST, etc.)
        if is_allowed:
            async def send_wrapper(message: dict) -> None:
                if message["type"] == "http.response.start":
                    cors_headers = self._get_cors_headers(origin)
                    # Injeta cabeçalhos CORS com segurança na resposta final
                    existing_headers = list(message.get("headers", []))
                    existing_headers.extend(cors_headers)
                    message["headers"] = existing_headers
                await send(message)

            await self.app(scope, receive, send_wrapper)
        else:
            # Bloqueia a resposta de requisições não autorizadas por segurança
            await self._send_response(send, status=403, headers=[(b"content-type", b"text/plain")])

    def _is_origin_allowed(self, origin: str) -> bool:
        """
        Valida se a Origem está explicitamente na lista ou corresponde ao padrão Regex.
        Previne ataques de Origin Bypassing (ex: 'minhaplataforma.com.br.attacker.com').
        """
        if origin in self.allowed_explicit_origins:
            return True
        return bool(self.allowed_origin_regex.match(origin))

    def _get_cors_headers(self, origin: str) -> List[tuple]:
        """
        Gera os cabeçalhos CORS.
        Importante: Nunca utiliza '*' quando 'Access-Control-Allow-Credentials' é True.
        """
        return [
            (b"access-control-allow-origin", origin.encode("latin1")),
            (b"access-control-allow-credentials", b"true"),
            (b"vary", b"Origin"),
        ]

    def _get_preflight_headers(self, origin: str) -> List[tuple]:
        headers = self._get_cors_headers(origin)
        headers.extend([
            (b"access-control-allow-methods", ", ".join(self.allowed_methods).encode("latin1")),
            (b"access-control-allow-headers", ", ".join(self.allowed_headers).encode("latin1")),
            (b"access-control-max-age", str(self.max_age).encode("latin1")),
        ])
        return headers

    async def _send_response(self, send: Send, status: int, headers: List[tuple]) -> None:
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": headers,
        })
        await send({
            "type": "http.response.body",
            "body": b"Forbidden" if status == 403 else b"",
        })