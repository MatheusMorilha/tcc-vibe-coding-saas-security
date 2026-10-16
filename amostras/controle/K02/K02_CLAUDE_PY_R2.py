"""
cors.py - Middleware ASGI de CORS para a API pública da plataforma SaaS.

Princípios de segurança (OWASP Top 10: A01 Broken Access Control,
A02 Security Misconfiguration, A04 Insecure Design, A05, A09 Logging):

  * Nunca refletir o Origin cegamente e nunca usar "*" junto com credenciais.
  * Allowlist com comparação EXATA de origem canônica (esquema + host + porta).
  * Origem "null", múltiplos cabeçalhos Origin, userinfo, path etc. são rejeitados.
  * HTTPS obrigatório (http apenas para localhost, e só se habilitado).
  * Origens por tenant resolvidas por callback assíncrono (falha fechada),
    com cache TTL limitado para evitar DoS na base de dados.
  * Preflight valida método e cabeçalhos solicitados contra allowlist.
  * "Vary: Origin" sempre presente (evita envenenamento de cache).
  * Defesa em profundidade contra CSRF: requisições mutáveis vindas de
    origem não confiável são bloqueadas (CORS sozinho NÃO protege contra CSRF).
  * Logs sanitizados (sem injeção de log).
"""
from __future__ import annotations

import logging
import re
import time
from collections import OrderedDict
from typing import Awaitable, Callable, Iterable, Optional
from urllib.parse import urlsplit

logger = logging.getLogger("api.cors")

OriginResolver = Callable[[str], Awaitable[bool]]

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_HEADER_NAME_RE = re.compile(r"^[a-z0-9!#$%&'*+.^_`|~-]{1,64}$")
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1"})
_MAX_ORIGIN_LEN = 255


def _log_safe(value: str) -> str:
    """Remove caracteres de controle e trunca (evita log injection)."""
    return re.sub(r"[^\x20-\x7e]", "?", value)[:100]


def normalize_origin(raw: str, *, allow_localhost: bool = False) -> Optional[str]:
    """
    Converte um Origin em sua forma canônica 'esquema://host[:porta]'
    ou devolve None se for inválido/inseguro.
    """
    if not raw or len(raw) > _MAX_ORIGIN_LEN or raw.lower() == "null":
        return None
    if any(c in raw for c in ("\r", "\n", "\x00", " ", "\\", "*")):
        return None
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower()
        port = parts.port  # ValueError se porta inválida
    except ValueError:
        return None

    if parts.username or parts.password or parts.path or parts.query or parts.fragment:
        return None
    if not host or not _HOST_RE.match(host):
        return None

    scheme = parts.scheme.lower()
    is_local = host in _LOCAL_HOSTS
    if scheme == "https":
        default_port = 443
    elif scheme == "http" and is_local and allow_localhost:
        default_port = 80
    else:
        return None

    netloc = host if port in (None, default_port) else f"{host}:{port}"
    return f"{scheme}://{netloc}"


class _TTLCache:
    """Cache LRU com TTL e tamanho máximo (proteção contra exaustão de memória)."""

    def __init__(self, max_size: int = 2048) -> None:
        self._data: "OrderedDict[str, tuple[float, bool]]" = OrderedDict()
        self._max = max_size

    def get(self, key: str) -> Optional[bool]:
        item = self._data.get(key)
        if item is None:
            return None
        expires, value = item
        if expires < time.monotonic():
            self._data.pop(key, None)
            return None
        self._data.move_to_end(key)
        return value

    def set(self, key: str, value: bool, ttl: float) -> None:
        self._data[key] = (time.monotonic() + ttl, value)
        self._data.move_to_end(key)
        while len(self._data) > self._max:
            self._data.popitem(last=False)


class CORSMiddleware:
    def __init__(
        self,
        app,
        *,
        allowed_origins: Iterable[str] = (),
        origin_resolver: Optional[OriginResolver] = None,
        allowed_methods: Iterable[str] = ("GET", "POST", "PUT", "PATCH", "DELETE"),
        allowed_headers: Iterable[str] = (
            "accept", "content-type", "x-csrf-token", "x-request-id",
        ),
        expose_headers: Iterable[str] = ("x-request-id",),
        max_age: int = 600,
        allow_localhost: bool = False,
        block_untrusted_unsafe_methods: bool = True,
        positive_ttl: float = 300.0,
        negative_ttl: float = 60.0,
    ) -> None:
        self.app = app
        self.allow_localhost = allow_localhost
        self.resolver = origin_resolver
        self.block_untrusted = block_untrusted_unsafe_methods
        self.positive_ttl = positive_ttl
        self.negative_ttl = negative_ttl
        self._cache = _TTLCache()

        # Allowlist estática: falha na inicialização se houver configuração insegura.
        self.static_origins: set[str] = set()
        for o in allowed_origins:
            canon = normalize_origin(o, allow_localhost=allow_localhost)
            if canon is None:
                raise ValueError(f"Origem CORS inválida/insegura na configuração: {o!r}")
            self.static_origins.add(canon)

        self.methods = frozenset(m.upper() for m in allowed_methods)
        if not self.methods <= {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("Métodos CORS não suportados na configuração.")

        self.req_headers = frozenset(h.lower() for h in allowed_headers)
        self.expose = tuple(h.lower() for h in expose_headers)
        for h in (*self.req_headers, *self.expose):
            if h == "*" or not _HEADER_NAME_RE.match(h):
                raise ValueError(f"Cabeçalho CORS inválido: {h!r}")

        self.max_age = max(0, min(int(max_age), 7200))  # limite superior

        self._allow_methods_value = ", ".join(sorted(self.methods | {"OPTIONS"}))
        self._allow_headers_value = ", ".join(sorted(self.req_headers))
        self._expose_value = ", ".join(self.expose)

    # ------------------------------------------------------------------ ASGI
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = self._collect_headers(scope)
        method = scope["method"].upper()
        origin_values = headers.get("origin", [])

        # Sem Origin: não é requisição cross-origin de navegador.
        if not origin_values:
            await self.app(scope, receive, self._wrap_send(send, None))
            return

        # Múltiplos Origin => requisição ambígua/maliciosa.
        origin = (
            normalize_origin(origin_values[0], allow_localhost=self.allow_localhost)
            if len(origin_values) == 1 else None
        )
        trusted = origin is not None and await self._is_allowed(origin)
        is_preflight = method == "OPTIONS" and "access-control-request-method" in headers

        if is_preflight:
            await self._handle_preflight(send, headers, origin if trusted else None)
            return

        if not trusted:
            same_origin = origin is not None and origin == self._request_origin(scope, headers)
            if self.block_untrusted and method not in _SAFE_METHODS and not same_origin:
                logger.warning(
                    "CORS: %s bloqueado de origem não confiável %s",
                    _log_safe(method), _log_safe(origin_values[0]),
                )
                await self._respond(send, 403, b'{"error":"origin_not_allowed"}', None)
                return
            # Segue sem cabeçalhos CORS: o navegador bloqueia a leitura da resposta.
            await self.app(scope, receive, self._wrap_send(send, None))
            return

        await self.app(scope, receive, self._wrap_send(send, origin))

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _collect_headers(scope) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for k, v in scope.get("headers", []):
            out.setdefault(k.decode("latin-1").lower(), []).append(v.decode("latin-1"))
        return out

    @staticmethod
    def _request_origin(scope, headers) -> Optional[str]:
        host = (headers.get("host") or [""])[0].lower()
        scheme = scope.get("scheme", "https")
        return f"{scheme}://{host}" if host else None

    async def _is_allowed(self, origin: str) -> bool:
        if origin in self.static_origins:
            return True
        if self.resolver is None:
            return False
        cached = self._cache.get(origin)
        if cached is not None:
            return cached
        try:
            allowed = bool(await self.resolver(origin))
        except Exception:  # falha fechada: nunca libera em caso de erro
            logger.exception("CORS: falha ao resolver origem de tenant")
            return False
        self._cache.set(origin, allowed, self.positive_ttl if allowed else self.negative_ttl)
        return allowed

    async def _handle_preflight(self, send, headers, origin: Optional[str]) -> None:
        if origin is None:
            await self._respond(send, 403, b"", None, preflight=True)
            return

        req_method = (headers["access-control-request-method"][0]).strip().upper()
        raw_req_headers = ",".join(headers.get("access-control-request-headers", []))
        req_headers = {h.strip().lower() for h in raw_req_headers.split(",") if h.strip()}

        if req_method not in self.methods or not req_headers <= self.req_headers:
            logger.info("CORS: preflight rejeitado (%s)", _log_safe(req_method))
            await self._respond(send, 403, b"", None, preflight=True)
            return

        await self._respond(
            send, 204, b"", origin, preflight=True,
            extra=[
                (b"access-control-allow-methods", self._allow_methods_value.encode()),
                (b"access-control-allow-headers", self._allow_headers_value.encode()),
                (b"access-control-max-age", str(self.max_age).encode()),
            ],
        )

    def _cors_headers(self, origin: Optional[str]) -> list[tuple[bytes, bytes]]:
        if origin is None:
            return []
        h = [
            (b"access-control-allow-origin", origin.encode("ascii")),
            (b"access-control-allow-credentials", b"true"),
        ]
        if self._expose_value:
            h.append((b"access-control-expose-headers", self._expose_value.encode()))
        return h

    async def _respond(self, send, status, body, origin, *, preflight=False, extra=()):
        headers = [
            (b"vary", b"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
             if preflight else b"Origin"),
            (b"content-length", str(len(body)).encode()),
            (b"cache-control", b"no-store"),
            (b"x-content-type-options", b"nosniff"),
        ]
        if body:
            headers.append((b"content-type", b"application/json"))
        headers += self._cors_headers(origin) + list(extra)
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    def _wrap_send(self, send, origin: Optional[str]):
        cors = self._cors_headers(origin)

        async def wrapper(message):
            if message["type"] == "http.response.start":
                # Remove CORS vindo de camadas internas (evita valores conflitantes).
                kept = [
                    (k, v) for k, v in message.get("headers", [])
                    if not k.lower().startswith(b"access-control-")
                ]
                vary_idx = next((i for i, (k, _) in enumerate(kept) if k.lower() == b"vary"), None)
                if vary_idx is None:
                    kept.append((b"vary", b"Origin"))
                elif b"origin" not in kept[vary_idx][1].lower() and kept[vary_idx][1].strip() != b"*":
                    kept[vary_idx] = (kept[vary_idx][0], kept[vary_idx][1] + b", Origin")
                message = {**message, "headers": kept + cors}
            await send(message)

        return wrapper


# ------------------------------------------------------------------ Exemplo
# from fastapi import FastAPI
#
# async def tenant_origin_exists(origin: str) -> bool:
#     # Consulta PARAMETRIZADA (sem concatenar strings) à tabela de domínios
#     # cadastrados e verificados dos tenants, apenas de assinaturas ativas:
#     #   SELECT 1 FROM tenant_allowed_origins o
#     #   JOIN subscriptions s ON s.tenant_id = o.tenant_id
#     #   WHERE o.origin = :origin AND o.verified AND s.status = 'active'
#     ...
#
# app = FastAPI()
# app.add_middleware(
#     CORSMiddleware,
#     allowed_origins=["https://app.minhaplataforma.com"],
#     origin_resolver=tenant_origin_exists,
#     max_age=600,
# )