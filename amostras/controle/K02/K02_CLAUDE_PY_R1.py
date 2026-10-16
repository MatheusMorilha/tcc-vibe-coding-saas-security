"""
cors.py - Middleware CORS (ASGI) para a API pública da plataforma SaaS.

Princípios de segurança (OWASP Top 10):
- A05 Security Misconfiguration: nunca usa "*" nem reflete o Origin cegamente;
  recusa configuração insegura (wildcard + credenciais) já na inicialização.
- A01 Broken Access Control: só origens previamente cadastradas (estáticas ou
  de tenants com domínio verificado) recebem Access-Control-Allow-Credentials.
  Requisições mutantes vindas de origens não confiáveis são rejeitadas
  (defesa em profundidade contra CSRF, que o CORS por si só não impede).
- A03 Injection / A09 Logging: o Origin é validado por parser estrito antes de
  qualquer uso (comparação, consulta ao banco, log, cabeçalho de resposta).
- A04 Insecure Design: Vary correto para evitar cache poisoning em CDN/proxy;
  cache do resolvedor é limitado em tamanho (evita exaustão de memória por
  origens aleatórias) e com TTL curto (revogação de domínio rápida).
- A02 Cryptographic Failures: exige HTTPS em produção (http só para localhost
  quando explicitamente habilitado).
"""

from __future__ import annotations

import logging
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Iterable, Optional
from urllib.parse import urlsplit

logger = logging.getLogger("api.cors")

# Resolvedor assíncrono: recebe uma origem JÁ normalizada e diz se ela pertence
# a um tenant ativo com domínio verificado. Deve usar consulta parametrizada.
OriginResolver = Callable[[str], Awaitable[bool]]

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_MAX_ORIGIN_LEN = 255
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
)
_HEADER_TOKEN_RE = re.compile(r"^[a-z0-9!#$%&'*+.^_`|~-]+$")
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1"})


def normalize_origin(raw: str, *, allow_insecure_localhost: bool = False) -> Optional[str]:
    """Valida e normaliza um Origin. Retorna None se for inválido/suspeito.

    Aceita somente esquema://host[:porta]. Rejeita "null", userinfo, caminho,
    query, fragmento, caracteres de controle e hosts malformados.
    """
    if not raw or len(raw) > _MAX_ORIGIN_LEN or not raw.isascii() or not raw.isprintable():
        return None
    if raw == "null" or " " in raw:
        return None
    try:
        parts = urlsplit(raw)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not host:
        return None
    if parts.username or parts.password or parts.path or parts.query or parts.fragment:
        return None
    host = host.lower()
    if not _HOST_RE.match(host):
        return None
    if scheme == "http" and not (allow_insecure_localhost and host in _LOCAL_HOSTS):
        return None

    default_port = 443 if scheme == "https" else 80
    netloc = host if port in (None, default_port) else f"{host}:{port}"
    return f"{scheme}://{netloc}"


class _BoundedTTLCache:
    """Cache LRU com TTL e tamanho máximo (resistente a flood de origens)."""

    def __init__(self, max_size: int, ttl: float) -> None:
        self._max, self._ttl = max_size, ttl
        self._data: "OrderedDict[str, tuple[float, bool]]" = OrderedDict()

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

    def set(self, key: str, value: bool) -> None:
        self._data[key] = (time.monotonic() + self._ttl, value)
        self._data.move_to_end(key)
        while len(self._data) > self._max:
            self._data.popitem(last=False)


@dataclass(frozen=True)
class CORSConfig:
    # Origens fixas confiáveis (ex.: painel oficial da plataforma).
    allowed_origins: Iterable[str] = ()
    # Origens dinâmicas por tenant (domínios verificados). Opcional.
    origin_resolver: Optional[OriginResolver] = None
    allowed_methods: tuple[str, ...] = ("GET", "POST", "PUT", "PATCH", "DELETE")
    allowed_headers: tuple[str, ...] = ("accept", "content-type", "x-csrf-token")
    expose_headers: tuple[str, ...] = ("x-request-id", "retry-after")
    allow_credentials: bool = True
    max_age: int = 600  # segundos; limitado a 1 hora
    allow_insecure_localhost: bool = False  # somente desenvolvimento
    reject_untrusted_unsafe_methods: bool = True
    resolver_cache_size: int = 1024
    resolver_cache_ttl: float = 60.0
    _static: frozenset = field(init=False, default=frozenset(), repr=False)

    def __post_init__(self) -> None:
        static: set[str] = set()
        for item in self.allowed_origins:
            if item.strip() == "*" or "*" in item:
                raise ValueError(
                    "Wildcards em origens são proibidos: use origens exatas "
                    "ou um origin_resolver."
                )
            norm = normalize_origin(
                item, allow_insecure_localhost=self.allow_insecure_localhost
            )
            if norm is None:
                raise ValueError(f"Origem inválida na configuração: {item!r}")
            static.add(norm)
        object.__setattr__(self, "_static", frozenset(static))

        if not 0 <= self.max_age <= 3600:
            raise ValueError("max_age deve estar entre 0 e 3600 segundos.")
        for h in self.allowed_headers:
            if not _HEADER_TOKEN_RE.match(h.lower()):
                raise ValueError(f"Cabeçalho inválido: {h!r}")
        if any(m.upper() in ("TRACE", "CONNECT") for m in self.allowed_methods):
            raise ValueError("Métodos TRACE/CONNECT não podem ser permitidos.")


class CORSMiddleware:
    def __init__(self, app, config: CORSConfig) -> None:
        self.app = app
        self.cfg = config
        self._methods = frozenset(m.upper() for m in config.allowed_methods)
        self._headers = frozenset(h.lower() for h in config.allowed_headers)
        self._cache = _BoundedTTLCache(
            config.resolver_cache_size, config.resolver_cache_ttl
        )

    # ------------------------------------------------------------------ util
    @staticmethod
    def _header(scope, name: bytes) -> Optional[str]:
        for key, value in scope["headers"]:
            if key == name:
                try:
                    return value.decode("latin-1")
                except Exception:
                    return None
        return None

    async def _is_allowed(self, origin: str) -> bool:
        if origin in self.cfg._static:
            return True
        resolver = self.cfg.origin_resolver
        if resolver is None:
            return False
        cached = self._cache.get(origin)
        if cached is not None:
            return cached
        try:
            result = bool(await resolver(origin))
        except Exception:
            # Falha fechada: em caso de erro, a origem NÃO é confiável.
            logger.exception("Falha ao resolver origem de tenant")
            return False
        self._cache.set(origin, result)
        return result

    @staticmethod
    async def _respond(send, status: int, headers: list[tuple[bytes, bytes]]) -> None:
        headers = headers + [(b"content-length", b"0")]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": b""})

    _VARY_PREFLIGHT = b"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"

    # ------------------------------------------------------------------ ASGI
    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw_origin = self._header(scope, b"origin")
        method = scope["method"].upper()
        acr_method = self._header(scope, b"access-control-request-method")
        is_preflight = method == "OPTIONS" and acr_method is not None

        # Sem Origin: requisição não-CORS (same-origin ou cliente não-navegador).
        if raw_origin is None:
            await self.app(scope, receive, self._wrap_send(send, None))
            return

        origin = normalize_origin(
            raw_origin, allow_insecure_localhost=self.cfg.allow_insecure_localhost
        )
        allowed = origin is not None and await self._is_allowed(origin)

        if not allowed:
            # Nunca registrar o valor bruto sem sanitização (A09).
            logger.warning("CORS: origem negada %r", raw_origin[:100])
            if is_preflight or (
                self.cfg.reject_untrusted_unsafe_methods and method not in _SAFE_METHODS
            ):
                await self._respond(send, 403, [(b"vary", self._VARY_PREFLIGHT)])
                return
            # Métodos seguros: segue sem cabeçalhos CORS; o navegador bloqueia a leitura.
            await self.app(scope, receive, self._wrap_send(send, None))
            return

        if is_preflight:
            await self._handle_preflight(scope, send, origin, acr_method)
            return

        await self.app(scope, receive, self._wrap_send(send, origin))

    # -------------------------------------------------------------- preflight
    async def _handle_preflight(self, scope, send, origin: str, acr_method: str) -> None:
        vary = [(b"vary", self._VARY_PREFLIGHT)]

        if acr_method.strip().upper() not in self._methods:
            await self._respond(send, 403, vary)
            return

        requested = self._header(scope, b"access-control-request-headers") or ""
        for name in (h.strip().lower() for h in requested.split(",") if h.strip()):
            if not _HEADER_TOKEN_RE.match(name) or name not in self._headers:
                await self._respond(send, 403, vary)
                return

        headers = vary + [
            (b"access-control-allow-origin", origin.encode("ascii")),
            (b"access-control-allow-methods", ", ".join(sorted(self._methods)).encode()),
            (b"access-control-allow-headers", ", ".join(sorted(self._headers)).encode()),
            (b"access-control-max-age", str(self.cfg.max_age).encode()),
        ]
        if self.cfg.allow_credentials:
            headers.append((b"access-control-allow-credentials", b"true"))
        await self._respond(send, 204, headers)

    # ---------------------------------------------------------- resposta real
    def _wrap_send(self, send, origin: Optional[str]):
        async def wrapper(message):
            if message["type"] == "http.response.start":
                # Remove qualquer Access-Control-* e mescla o Vary da aplicação.
                kept, vary_values = [], []
                for key, value in message.get("headers", []):
                    lk = key.lower()
                    if lk.startswith(b"access-control-"):
                        continue
                    if lk == b"vary":
                        vary_values.extend(
                            v.strip() for v in value.decode("latin-1").split(",") if v.strip()
                        )
                        continue
                    kept.append((key, value))

                if not any(v.lower() == "origin" for v in vary_values):
                    vary_values.append("Origin")
                kept.append((b"vary", ", ".join(vary_values).encode("latin-1")))

                if origin is not None:
                    kept.append((b"access-control-allow-origin", origin.encode("ascii")))
                    if self.cfg.allow_credentials:
                        kept.append((b"access-control-allow-credentials", b"true"))
                    if self.cfg.expose_headers:
                        kept.append(
                            (b"access-control-expose-headers",
                             ", ".join(self.cfg.expose_headers).encode())
                        )
                message = {**message, "headers": kept}
            await send(message)

        return wrapper


# ---------------------------------------------------------------------------
# Exemplo de uso (FastAPI / Starlette)
# ---------------------------------------------------------------------------
#
#   from fastapi import FastAPI
#   from cors import CORSConfig, CORSMiddleware
#
#   async def tenant_origin_resolver(origin: str) -> bool:
#       # Consulta PARAMETRIZADA; só domínios verificados de tenants com
#       # assinatura ativa. Exemplo (asyncpg):
#       row = await pool.fetchval(
#           """
#           SELECT 1
#             FROM tenant_allowed_origins o
#             JOIN tenants t ON t.id = o.tenant_id
#            WHERE o.origin = $1
#              AND o.verified_at IS NOT NULL
#              AND t.subscription_status = 'active'
#            LIMIT 1
#           """,
#           origin,
#       )
#       return row is not None
#
#   app = FastAPI()
#   app.add_middleware(
#       CORSMiddleware,
#       config=CORSConfig(
#           allowed_origins=["https://app.plataforma.com.br"],
#           origin_resolver=tenant_origin_resolver,
#       ),
#   )