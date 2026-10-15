"""
Middleware de CORS para a API pública da plataforma SaaS multilocatária.

Puro ASGI (sem dependências): funciona com FastAPI, Starlette, Django (ASGI), etc.

Decisões de segurança:
  * Credenciais habilitadas (Access-Control-Allow-Credentials: true) => NUNCA usa "*".
    A origem é validada e devolvida de forma explícita.
  * Origem nunca é refletida às cegas: precisa estar na lista estática, casar com
    um regex restrito OU ser aprovada pelo validador (ex.: domínios cadastrados
    pelo tenant).
  * Falha fechada: erro no validador => origem negada.
  * "null" e origens malformadas são sempre negadas.
  * Vary: Origin sempre presente, evitando que caches misturem respostas.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Awaitable, Callable, Iterable, MutableMapping, Optional
from urllib.parse import urlsplit

logger = logging.getLogger("api.cors")

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

# async (origem_normalizada, scope) -> bool
OriginValidator = Callable[[str, Scope], Awaitable[bool]]

DEFAULT_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
DEFAULT_HEADERS = ("Authorization", "Content-Type", "Accept", "X-CSRF-Token", "X-Request-ID")


def normalize_origin(raw: Optional[str]) -> Optional[str]:
    """Normaliza 'scheme://host[:porta]'. Retorna None se inválida."""
    if not raw or raw.strip().lower() == "null":
        return None
    try:
        parts = urlsplit(raw.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        return None
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
        return None
    host = parts.hostname.lower()
    if ":" in host:  # IPv6
        host = f"[{host}]"
    default_port = 443 if scheme == "https" else 80
    netloc = host if port in (None, default_port) else f"{host}:{port}"
    return f"{scheme}://{netloc}"


class CORSMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_origins: Iterable[str] = (),
        allowed_origin_regex: Optional[str] = None,
        origin_validator: Optional[OriginValidator] = None,
        allow_methods: Iterable[str] = DEFAULT_METHODS,
        allow_headers: Iterable[str] = DEFAULT_HEADERS,
        expose_headers: Iterable[str] = (),
        max_age: int = 600,
    ) -> None:
        self.app = app
        self.allowed_origins = set()
        for origin in allowed_origins:
            if origin.strip() == "*":
                raise ValueError("Wildcard '*' é incompatível com credenciais; liste as origens.")
            normalized = normalize_origin(origin)
            if normalized is None:
                raise ValueError(f"Origem inválida na configuração de CORS: {origin!r}")
            self.allowed_origins.add(normalized)

        self.origin_regex = re.compile(allowed_origin_regex) if allowed_origin_regex else None
        self.origin_validator = origin_validator
        self.allow_methods = tuple(m.upper() for m in allow_methods)
        self.allow_headers = tuple(allow_headers)
        self._allow_headers_lower = {h.lower() for h in self.allow_headers}
        self.expose_headers = tuple(expose_headers)
        self.max_age = max_age

    # ------------------------------------------------------------------ ASGI
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        raw_origin = headers.get("origin")

        # Sem Origin: não é requisição cross-origin de navegador.
        if raw_origin is None:
            await self.app(scope, receive, send)
            return

        origin = normalize_origin(raw_origin)
        allowed = origin is not None and await self._is_origin_allowed(origin, scope)

        is_preflight = (
            scope["method"] == "OPTIONS" and "access-control-request-method" in headers
        )
        if is_preflight:
            await self._handle_preflight(send, origin, allowed, headers)
            return

        await self.app(scope, receive, self._wrap_send(send, origin if allowed else None))

    # ------------------------------------------------------------- Validação
    async def _is_origin_allowed(self, origin: str, scope: Scope) -> bool:
        if origin in self.allowed_origins:
            return True
        if self.origin_regex and self.origin_regex.fullmatch(origin):
            return True
        if self.origin_validator:
            try:
                return bool(await self.origin_validator(origin, scope))
            except Exception:  # falha fechada
                logger.exception("Erro ao validar origem CORS %s", origin)
        return False

    # -------------------------------------------------------------- Preflight
    async def _handle_preflight(
        self, send: Send, origin: Optional[str], allowed: bool, req_headers: dict
    ) -> None:
        vary = b"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
        requested_method = req_headers.get("access-control-request-method", "").upper()
        requested_headers = [
            h.strip().lower()
            for h in req_headers.get("access-control-request-headers", "").split(",")
            if h.strip()
        ]

        ok = (
            allowed
            and requested_method in self.allow_methods
            and all(h in self._allow_headers_lower for h in requested_headers)
        )
        if not ok:
            # Sem cabeçalhos CORS: o navegador bloqueia a requisição real.
            await self._send_simple(send, 403, [(b"vary", vary), (b"content-type", b"text/plain")], b"CORS preflight negado")
            return

        response_headers = [
            (b"access-control-allow-origin", origin.encode("latin-1")),
            (b"access-control-allow-credentials", b"true"),
            (b"access-control-allow-methods", ", ".join(self.allow_methods).encode()),
            (b"access-control-allow-headers", ", ".join(self.allow_headers).encode()),
            (b"access-control-max-age", str(self.max_age).encode()),
            (b"vary", vary),
        ]
        await self._send_simple(send, 204, response_headers, b"")

    @staticmethod
    async def _send_simple(send: Send, status: int, headers: list, body: bytes) -> None:
        headers = headers + [(b"content-length", str(len(body)).encode())]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    # ------------------------------------------------------ Requisição real
    def _wrap_send(self, send: Send, allowed_origin: Optional[str]) -> Send:
        async def wrapped(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                if allowed_origin:
                    headers.append((b"access-control-allow-origin", allowed_origin.encode("latin-1")))
                    headers.append((b"access-control-allow-credentials", b"true"))
                    if self.expose_headers:
                        headers.append((b"access-control-expose-headers", ", ".join(self.expose_headers).encode()))
                message["headers"] = self._merge_vary(headers, b"Origin")
            await send(message)

        return wrapped

    @staticmethod
    def _merge_vary(headers: list, value: bytes) -> list:
        """Acrescenta 'Vary: <value>' preservando valores já existentes."""
        existing = [v for k, v in headers if k.lower() == b"vary"]
        rest = [(k, v) for k, v in headers if k.lower() != b"vary"]
        tokens = [t.strip() for v in existing for t in v.split(b",") if t.strip()]
        if b"*" not in tokens and value.lower() not in (t.lower() for t in tokens):
            tokens.append(value)
        rest.append((b"vary", b", ".join(tokens)))
        return rest


# ---------------------------------------------------------------------------
# Suporte multilocatário: origens cadastradas por empresa, com cache em memória
# ---------------------------------------------------------------------------
class TenantOriginValidator:
    """
    Valida a origem contra os domínios que as empresas cadastraram (ex.: tabela
    `tenant_allowed_origins`). Só empresas com assinatura ativa são aceitas.

    `lookup(origin) -> bool` deve consultar a base com query parametrizada, por
    exemplo:
        SELECT 1 FROM tenant_allowed_origins o
        JOIN tenants t ON t.id = o.tenant_id
        WHERE o.origin = :origin AND t.subscription_status = 'active'
    """

    def __init__(self, lookup: Callable[[str], Awaitable[bool]], ttl_seconds: int = 60,
                 max_entries: int = 10_000) -> None:
        self._lookup = lookup
        self._ttl = ttl_seconds
        self._max = max_entries
        self._cache: dict[str, tuple[float, bool]] = {}

    async def __call__(self, origin: str, scope: Scope) -> bool:
        now = time.monotonic()
        hit = self._cache.get(origin)
        if hit and hit[0] > now:
            return hit[1]
        result = await self._lookup(origin)  # exceções propagam => negado pelo middleware
        if len(self._cache) >= self._max:
            self._cache.clear()  # proteção simples contra crescimento ilimitado
        self._cache[origin] = (now + self._ttl, result)
        return result


# ---------------------------------------------------------------------------
# Exemplo de uso (FastAPI/Starlette)
# ---------------------------------------------------------------------------
#   app = FastAPI()
#   app.add_middleware(
#       CORSMiddleware,
#       allowed_origins=["https://app.minhaplataforma.com"],
#       allowed_origin_regex=r"https://[a-z0-9-]+\.clientes\.minhaplataforma\.com",
#       origin_validator=TenantOriginValidator(buscar_origem_no_banco),
#       expose_headers=["X-Request-ID"],
#   )
#
# Cookies de sessão para uso cross-site: SameSite=None; Secure; HttpOnly.