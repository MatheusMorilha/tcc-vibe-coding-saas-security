"""
Middleware de CORS (Cross-Origin Resource Sharing) para a API pública da
plataforma SaaS multilocatária.

Objetivo
--------
Permitir que aplicações web hospedadas em outros domínios consumam a API e
enviem credenciais de sessão (cookies), com segurança.

Decisões de segurança
---------------------
1. Com credenciais, `Access-Control-Allow-Origin: *` é proibido pela
   especificação e perigoso. A origem NUNCA é refletida às cegas: ela só é
   devolvida se estiver cadastrada (allowlist) por uma empresa cliente ativa.
2. Comparação por igualdade exata de origem normalizada (esquema + host + porta).
   Sem regex, sem `endswith`, sem curingas. A origem "null" é sempre rejeitada.
3. `Vary: Origin` em toda resposta dependente de Origin, para que caches e CDNs
   não sirvam a resposta de uma origem para outra.
4. Preflight (OPTIONS) não carrega cookies e, portanto, não identifica o
   usuário/empresa. Ele é validado contra o conjunto de origens cadastradas
   por qualquer empresa ativa. O isolamento por empresa continua sendo
   garantido pela autenticação/autorização de cada requisição real.
5. Métodos e cabeçalhos permitidos são listas fechadas; cabeçalhos pedidos no
   preflight só são aceitos se estiverem na lista.
6. Em produção exige-se HTTPS (http só é aceito para localhost em modo dev).

Pré-requisitos fora deste arquivo
---------------------------------
* Cookie de sessão com `SameSite=None; Secure; HttpOnly` (necessário para o
  navegador enviá-lo em contexto cross-site).
* Proteção CSRF em endpoints que alteram estado (token por sessão enviado em
  cabeçalho customizado, ex.: X-CSRF-Token). CORS não substitui CSRF.

Uso (FastAPI/Starlette)
-----------------------
    app.add_middleware(
        CORSMiddleware,
        origin_repository=SqlOriginRepository(session_factory),
    )

Esquema sugerido para a persistência:

    CREATE TABLE tenant_allowed_origins (
        id         BIGSERIAL PRIMARY KEY,
        tenant_id  BIGINT NOT NULL REFERENCES tenants(id),
        origin     TEXT   NOT NULL,         -- já normalizada, ex.: https://app.cliente.com.br
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, origin)
    );
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Iterable, Protocol
from urllib.parse import urlsplit

logger = logging.getLogger("api.cors")

Scope = dict
Message = dict
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


# --------------------------------------------------------------------------- #
# Normalização de origem
# --------------------------------------------------------------------------- #
_DEFAULT_PORTS = {"http": 80, "https": 443}
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]"}


def normalize_origin(raw: str | None, *, allow_insecure_localhost: bool = False) -> str | None:
    """Normaliza uma origem (esquema://host[:porta]) ou devolve None se inválida.

    Rejeita: valor vazio, "null", caminho/query/fragmento, credenciais embutidas,
    esquemas diferentes de http/https e http fora de localhost (salvo em dev).
    """
    if not raw:
        return None
    raw = raw.strip()
    if raw.lower() == "null" or len(raw) > 255:
        return None

    try:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return None

    if scheme not in _DEFAULT_PORTS or not host:
        return None
    if parts.username or parts.password:
        return None
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return None

    if scheme == "http":
        is_local = host in _LOCAL_HOSTS
        if not (allow_insecure_localhost and is_local):
            return None

    if ":" in host:  # IPv6
        host = f"[{host}]"

    netloc = host if port in (None, _DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    return f"{scheme}://{netloc}"


# --------------------------------------------------------------------------- #
# Repositório de origens permitidas
# --------------------------------------------------------------------------- #
class OriginRepository(Protocol):
    """Contrato de consulta das origens cadastradas.

    A implementação real deve consultar `tenant_allowed_origins` fazendo JOIN
    com `tenants`/`subscriptions` para considerar apenas empresas com
    assinatura ativa, por exemplo:

        SELECT EXISTS (
            SELECT 1
              FROM tenant_allowed_origins o
              JOIN tenants t       ON t.id = o.tenant_id
              JOIN subscriptions s ON s.tenant_id = t.id
             WHERE o.origin = :origin
               AND t.is_active
               AND s.status = 'active'
        )
    """

    async def is_origin_registered(self, origin: str) -> bool: ...


@dataclass
class StaticOriginRepository:
    """Implementação em memória (testes, desenvolvimento, origens do próprio produto)."""

    origins: set[str] = field(default_factory=set)

    async def is_origin_registered(self, origin: str) -> bool:
        return origin in self.origins


class _TTLCache:
    """Cache assíncrono pequeno, com limite de tamanho e TTL (inclui cache negativo)."""

    def __init__(self, ttl: float, max_size: int) -> None:
        self._ttl = ttl
        self._max = max_size
        self._data: dict[str, tuple[float, bool]] = {}
        self._lock = asyncio.Lock()

    def get(self, key: str) -> bool | None:
        item = self._data.get(key)
        if item is None:
            return None
        expires_at, value = item
        if expires_at < time.monotonic():
            self._data.pop(key, None)
            return None
        return value

    async def set(self, key: str, value: bool) -> None:
        async with self._lock:
            if len(self._data) >= self._max:
                now = time.monotonic()
                self._data = {k: v for k, v in self._data.items() if v[0] > now}
                if len(self._data) >= self._max:  # ainda cheio: descarta o mais antigo
                    self._data.pop(min(self._data, key=lambda k: self._data[k][0]))
            self._data[key] = (time.monotonic() + self._ttl, value)


# --------------------------------------------------------------------------- #
# Middleware
# --------------------------------------------------------------------------- #
DEFAULT_ALLOW_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
DEFAULT_ALLOW_HEADERS = (
    "Accept",
    "Content-Type",
    "Authorization",
    "X-CSRF-Token",
    "X-Request-ID",
)
DEFAULT_EXPOSE_HEADERS = (
    "X-Request-ID",
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "Retry-After",
)


class CORSMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        origin_repository: OriginRepository,
        allow_methods: Iterable[str] = DEFAULT_ALLOW_METHODS,
        allow_headers: Iterable[str] = DEFAULT_ALLOW_HEADERS,
        expose_headers: Iterable[str] = DEFAULT_EXPOSE_HEADERS,
        allow_credentials: bool = True,
        max_age: int = 600,
        cache_ttl: float = 60.0,
        cache_max_size: int = 2048,
        allow_insecure_localhost: bool = False,
    ) -> None:
        self.app = app
        self.repo = origin_repository
        self.allow_methods = tuple(m.upper() for m in allow_methods)
        self._allow_methods_set = frozenset(self.allow_methods)
        self.allow_headers = tuple(allow_headers)
        self._allow_headers_lower = frozenset(h.lower() for h in self.allow_headers)
        self.expose_headers = tuple(expose_headers)
        self.allow_credentials = allow_credentials
        self.max_age = max_age
        self.allow_insecure_localhost = allow_insecure_localhost
        self._cache = _TTLCache(cache_ttl, cache_max_size)

    # ------------------------------------------------------------------ ASGI
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = _Headers(scope["headers"])
        raw_origin = headers.get("origin")

        # Requisição sem Origin (same-origin, curl, servidor-a-servidor): não é CORS.
        if raw_origin is None:
            await self.app(scope, receive, send)
            return

        origin = await self._resolve_allowed_origin(raw_origin)
        is_preflight = (
            scope["method"] == "OPTIONS"
            and headers.get("access-control-request-method") is not None
        )

        if is_preflight:
            await self._handle_preflight(origin, headers, send)
            return

        await self.app(scope, receive, self._wrap_send(send, origin))

    # ------------------------------------------------------------ Validação
    async def _resolve_allowed_origin(self, raw_origin: str) -> str | None:
        origin = normalize_origin(
            raw_origin, allow_insecure_localhost=self.allow_insecure_localhost
        )
        if origin is None:
            return None

        cached = self._cache.get(origin)
        if cached is not None:
            return origin if cached else None

        try:
            allowed = await self.repo.is_origin_registered(origin)
        except Exception:  # falha fechada: sem consulta, sem CORS
            logger.exception("Falha ao consultar origens permitidas")
            return None

        await self._cache.set(origin, bool(allowed))
        return origin if allowed else None

    # ------------------------------------------------------------ Preflight
    async def _handle_preflight(
        self, origin: str | None, headers: "_Headers", send: Send
    ) -> None:
        vary = b"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"

        if origin is None:
            await _respond(send, 403, [(b"vary", vary)], b"Origem nao permitida")
            return

        method = (headers.get("access-control-request-method") or "").upper()
        if method not in self._allow_methods_set:
            await _respond(send, 403, [(b"vary", vary)], b"Metodo nao permitido")
            return

        requested = headers.get("access-control-request-headers")
        if requested:
            names = [h.strip().lower() for h in requested.split(",") if h.strip()]
            if any(n not in self._allow_headers_lower for n in names):
                await _respond(send, 403, [(b"vary", vary)], b"Cabecalho nao permitido")
                return

        response_headers = [
            (b"vary", vary),
            (b"access-control-allow-origin", origin.encode("latin-1")),
            (b"access-control-allow-methods", ", ".join(self.allow_methods).encode()),
            (b"access-control-allow-headers", ", ".join(self.allow_headers).encode()),
            (b"access-control-max-age", str(self.max_age).encode()),
        ]
        if self.allow_credentials:
            response_headers.append((b"access-control-allow-credentials", b"true"))

        await _respond(send, 204, response_headers, b"")

    # ------------------------------------------------------ Resposta normal
    def _wrap_send(self, send: Send, origin: str | None) -> Send:
        async def wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                _merge_vary(headers, b"Origin")

                if origin is not None:
                    headers = [
                        (k, v)
                        for k, v in headers
                        if k.lower()
                        not in (
                            b"access-control-allow-origin",
                            b"access-control-allow-credentials",
                            b"access-control-expose-headers",
                        )
                    ]
                    headers.append((b"access-control-allow-origin", origin.encode("latin-1")))
                    if self.allow_credentials:
                        headers.append((b"access-control-allow-credentials", b"true"))
                    if self.expose_headers:
                        headers.append(
                            (b"access-control-expose-headers", ", ".join(self.expose_headers).encode())
                        )
                message = {**message, "headers": headers}
            await send(message)

        return wrapped


# --------------------------------------------------------------------------- #
# Utilitários
# --------------------------------------------------------------------------- #
class _Headers:
    """Acesso case-insensitive aos cabeçalhos do scope ASGI."""

    def __init__(self, raw: list[tuple[bytes, bytes]]) -> None:
        self._h = {k.lower(): v for k, v in raw}

    def get(self, name: str) -> str | None:
        value = self._h.get(name.lower().encode("latin-1"))
        return value.decode("latin-1") if value is not None else None


def _merge_vary(headers: list[tuple[bytes, bytes]], value: bytes) -> None:
    """Acrescenta `value` ao Vary existente (ou cria), sem duplicar."""
    for i, (k, v) in enumerate(headers):
        if k.lower() == b"vary":
            tokens = [t.strip() for t in v.split(b",") if t.strip()]
            if value.lower() not in (t.lower() for t in tokens) and b"*" not in tokens:
                headers[i] = (k, b", ".join(tokens + [value]))
            return
    headers.append((b"vary", value))


async def _respond(
    send: Send, status: int, headers: list[tuple[bytes, bytes]], body: bytes
) -> None:
    headers = headers + [(b"content-length", str(len(body)).encode())]
    if body:
        headers.append((b"content-type", b"text/plain; charset=utf-8"))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})