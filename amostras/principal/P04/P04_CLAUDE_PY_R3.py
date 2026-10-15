"""
Middleware CORS ASGI para API pública SaaS multilocatária.

- Sem dependências externas (compatível com FastAPI, Starlette, Litestar etc.)
- Allowlist por tenant + allowlist global da plataforma
- Suporte a credenciais (cookies de sessão) sem nunca usar "*"
"""
from __future__ import annotations

import logging
import time
from typing import Awaitable, Callable, Iterable, Optional, Protocol
from urllib.parse import urlsplit

logger = logging.getLogger("api.cors")

Scope = dict
Receive = Callable[[], Awaitable[dict]]
Send = Callable[[dict], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]
TenantResolver = Callable[[Scope], Optional[str]]


# --------------------------------------------------------------------------
# Normalização de origens
# --------------------------------------------------------------------------
def normalize_origin(value: str | None, *, allow_local_http: bool = False) -> Optional[str]:
    """
    Retorna a origem canônica (scheme://host[:porta]) ou None se inválida.
    Usar tanto ao cadastrar origens de um tenant quanto ao ler o header Origin.
    """
    if not value or value == "null" or len(value) > 255 or "*" in value:
        return None
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None

    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if (
        not host
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or parts.username
        or parts.password
    ):
        return None

    if scheme == "https":
        default_port = 443
    elif scheme == "http" and allow_local_http and host in {"localhost", "127.0.0.1", "::1"}:
        default_port = 80
    else:
        return None

    if ":" in host:  # IPv6
        host = f"[{host}]"
    suffix = f":{port}" if port and port != default_port else ""
    return f"{scheme}://{host}{suffix}"


# --------------------------------------------------------------------------
# Provedores de origens permitidas
# --------------------------------------------------------------------------
class TenantOriginProvider(Protocol):
    async def get_allowed_origins(self, tenant_key: str) -> Iterable[str]:
        """Origens cadastradas para o tenant (ex.: SELECT em tenant_allowed_origins)."""
        ...


class CachedTenantOriginProvider:
    """Cache TTL em memória para não consultar o banco a cada requisição/preflight."""

    def __init__(self, inner: TenantOriginProvider, ttl_seconds: float = 60.0, max_entries: int = 10_000):
        self._inner = inner
        self._ttl = ttl_seconds
        self._max = max_entries
        self._cache: dict[str, tuple[float, frozenset[str]]] = {}

    async def get_allowed_origins(self, tenant_key: str) -> frozenset[str]:
        now = time.monotonic()
        hit = self._cache.get(tenant_key)
        if hit and hit[0] > now:
            return hit[1]

        origins = frozenset(
            o for o in (normalize_origin(x) for x in await self._inner.get_allowed_origins(tenant_key)) if o
        )
        if len(self._cache) >= self._max:
            self._cache.clear()  # política simples; troque por LRU/Redis se necessário
        self._cache[tenant_key] = (now + self._ttl, origins)
        return origins

    def invalidate(self, tenant_key: str) -> None:
        """Chamar quando o tenant alterar suas origens permitidas."""
        self._cache.pop(tenant_key, None)


def subdomain_tenant_resolver(base_domain: str) -> TenantResolver:
    """
    Resolve o tenant pelo host: 'acme.api.plataforma.com' -> 'acme'.
    O Host está presente no preflight (cookies não), por isso é a fonte da verdade.
    """
    base = base_domain.lower().lstrip(".")

    def resolve(scope: Scope) -> Optional[str]:
        host = _get_header(scope, b"host")
        if not host:
            return None
        host = host.split(":")[0].lower()
        if host.endswith("." + base):
            label = host[: -(len(base) + 1)]
            if label and "." not in label:
                return label
        return None

    return resolve


# --------------------------------------------------------------------------
# Utilitários ASGI
# --------------------------------------------------------------------------
def _get_header(scope: Scope, name: bytes) -> Optional[str]:
    for key, value in scope.get("headers", []):
        if key == name:
            return value.decode("latin-1")
    return None


def _merge_vary(headers: list[tuple[bytes, bytes]], *values: str) -> None:
    existing: list[str] = []
    for i, (k, v) in enumerate(headers):
        if k.lower() == b"vary":
            existing = [p.strip() for p in v.decode("latin-1").split(",") if p.strip()]
            del headers[i]
            break
    present = {p.lower() for p in existing}
    for val in values:
        if val.lower() not in present:
            existing.append(val)
    headers.append((b"vary", ", ".join(existing).encode("latin-1")))


async def _plain_response(send: Send, status: int, headers: list[tuple[bytes, bytes]], body: bytes = b"") -> None:
    headers = headers + [(b"content-length", str(len(body)).encode())]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


# --------------------------------------------------------------------------
# Middleware
# --------------------------------------------------------------------------
class TenantCORSMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        tenant_resolver: TenantResolver,
        origin_provider: TenantOriginProvider,
        platform_origins: Iterable[str] = (),
        allow_methods: Iterable[str] = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"),
        allow_headers: Iterable[str] = (
            "Authorization", "Content-Type", "Accept",
            "X-Requested-With", "X-CSRF-Token", "Idempotency-Key",
        ),
        expose_headers: Iterable[str] = ("X-Request-ID", "Retry-After", "X-RateLimit-Remaining"),
        max_age: int = 600,
        allow_credentials: bool = True,
        allow_local_http: bool = False,  # True somente em desenvolvimento
    ) -> None:
        self.app = app
        self.tenant_resolver = tenant_resolver
        self.origin_provider = origin_provider
        self.allow_local_http = allow_local_http
        self.platform_origins = frozenset(
            o for o in (normalize_origin(x, allow_local_http=allow_local_http) for x in platform_origins) if o
        )
        self.allow_methods = tuple(m.upper() for m in allow_methods)
        self.allow_headers = tuple(allow_headers)
        self._allow_headers_lc = {h.lower() for h in self.allow_headers}
        self.expose_headers = tuple(expose_headers)
        self.max_age = max_age
        self.allow_credentials = allow_credentials

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw_origin = _get_header(scope, b"origin")
        if raw_origin is None:  # requisição same-origin / não-browser
            await self.app(scope, receive, send)
            return

        origin = normalize_origin(raw_origin, allow_local_http=self.allow_local_http)
        allowed = origin is not None and await self._is_allowed(scope, origin)

        is_preflight = (
            scope["method"] == "OPTIONS"
            and _get_header(scope, b"access-control-request-method") is not None
        )
        if is_preflight:
            await self._handle_preflight(scope, send, origin if allowed else None)
            return

        async def send_wrapper(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                if allowed:
                    headers.append((b"access-control-allow-origin", origin.encode()))
                    if self.allow_credentials:
                        headers.append((b"access-control-allow-credentials", b"true"))
                    if self.expose_headers:
                        headers.append((b"access-control-expose-headers", ", ".join(self.expose_headers).encode()))
                _merge_vary(headers, "Origin")
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)

    # ------------------------------------------------------------------
    async def _is_allowed(self, scope: Scope, origin: str) -> bool:
        if origin in self.platform_origins:
            return True
        tenant_key = self.tenant_resolver(scope)
        if not tenant_key:
            return False  # sem tenant identificável: só origens da plataforma
        try:
            tenant_origins = await self.origin_provider.get_allowed_origins(tenant_key)
        except Exception:
            logger.exception("Falha ao carregar origens CORS do tenant; negando (fail-closed)")
            return False
        return origin in tenant_origins

    async def _handle_preflight(self, scope: Scope, send: Send, allowed_origin: Optional[str]) -> None:
        vary = [(b"vary", b"Origin, Access-Control-Request-Method, Access-Control-Request-Headers")]

        if allowed_origin is None:
            await _plain_response(send, 403, vary + [(b"content-type", b"text/plain")], b"CORS origin not allowed")
            return

        req_method = (_get_header(scope, b"access-control-request-method") or "").upper()
        req_headers = [
            h.strip().lower()
            for h in (_get_header(scope, b"access-control-request-headers") or "").split(",")
            if h.strip()
        ]
        if req_method not in self.allow_methods or any(h not in self._allow_headers_lc for h in req_headers):
            await _plain_response(send, 403, vary + [(b"content-type", b"text/plain")], b"CORS request not allowed")
            return

        headers = vary + [
            (b"access-control-allow-origin", allowed_origin.encode()),
            (b"access-control-allow-methods", ", ".join(self.allow_methods).encode()),
            (b"access-control-allow-headers", ", ".join(self.allow_headers).encode()),
            (b"access-control-max-age", str(self.max_age).encode()),
        ]
        if self.allow_credentials:
            headers.append((b"access-control-allow-credentials", b"true"))
        await _plain_response(send, 204, headers)