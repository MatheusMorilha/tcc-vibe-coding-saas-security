"""
Middleware CORS (ASGI puro) para a API pública da plataforma SaaS.

Objetivo: permitir que aplicações web hospedadas em outros domínios consumam
a API enviando credenciais de sessão (cookies), sem abrir brechas de segurança.

Decisões de segurança (OWASP Top 10):
- A01 Broken Access Control / A05 Security Misconfiguration:
    * Allowlist EXATA de origens (esquema + host + porta). Sem regex, sem
      curingas de subdomínio, sem refletir o header Origin cegamente.
    * Nunca emite "*" junto com credenciais; "null" é sempre rejeitado.
    * Validação da configuração na inicialização (falha rápida).
    * Preflight é respondido pelo próprio middleware e NUNCA chega à
      aplicação (não toca dados de nenhum tenant).
- A01 / A04 (defesa em profundidade contra CSRF):
    * Requisições não seguras (POST/PUT/PATCH/DELETE) com Origin não
      autorizado são rejeitadas com 403 antes de chegar à aplicação.
- A03 Injection: o valor de Origin só é ecoado após normalização estrita
  (ASCII imprimível, sem userinfo/caminho/query), evitando injeção de header.
- A02/A07: o middleware NÃO autentica nem autoriza. A sessão do usuário e o
  isolamento por tenant continuam sendo responsabilidade das camadas de
  autenticação/autorização da aplicação.
- A08 Cache poisoning: "Vary: Origin" é sempre enviado.
- A09 Logging: origens negadas são registradas (truncadas e sanitizadas).
- Falha fechada: qualquer erro no validador dinâmico resulta em negação.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Iterable, Optional
from urllib.parse import urlsplit

logger = logging.getLogger("app.security.cors")

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
_PRINTABLE_ASCII = re.compile(r"[\x21-\x7e]+")
_HEADER_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_MAX_ORIGIN_LEN = 255
_MAX_PREFLIGHT_AGE = 86_400

_CORS_RESPONSE_HEADERS = frozenset(
    {
        b"access-control-allow-origin",
        b"access-control-allow-credentials",
        b"access-control-expose-headers",
        b"access-control-allow-methods",
        b"access-control-allow-headers",
        b"access-control-max-age",
    }
)


def normalize_origin(value: str, *, strict_config: bool = False) -> Optional[str]:
    """Normaliza uma origem (esquema://host[:porta]) ou retorna None se inválida.

    O header Origin enviado por navegadores já é serializado nesse formato;
    qualquer coisa fora dele é tratada como inválida.
    """
    if not value or len(value) > _MAX_ORIGIN_LEN:
        return None
    if not _PRINTABLE_ASCII.fullmatch(value):
        return None  # espaços, CR/LF, controle ou não-ASCII
    if value.lower() == "null":
        return None
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None

    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        return None
    if not parts.hostname or parts.username is not None or parts.password is not None:
        return None
    if parts.path or parts.query or parts.fragment:
        return None
    if "*" in parts.hostname:
        return None

    host = parts.hostname.lower()
    if ":" in host:  # IPv6
        host = f"[{host}]"
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        host = f"{host}:{port}"
    return f"{scheme}://{host}"


OriginValidator = Callable[[str], Awaitable[bool]]


@dataclass(frozen=True)
class CorsConfig:
    """Configuração imutável do middleware.

    allowed_origins:   origens estáticas (ex.: o próprio front-end da plataforma).
    origin_validator:  coroutine opcional para origens dinâmicas por tenant
                       (ex.: domínios VERIFICADOS que cada empresa cadastrou).
                       Deve usar cache e consultar apenas domínios verificados.
    """

    allowed_origins: Iterable[str] = field(default_factory=tuple)
    origin_validator: Optional[OriginValidator] = None
    allowed_methods: tuple[str, ...] = ("GET", "POST", "PUT", "PATCH", "DELETE")
    # X-CSRF-Token (header customizado) força preflight e serve de proteção CSRF.
    allowed_headers: tuple[str, ...] = (
        "Content-Type",
        "Accept",
        "X-CSRF-Token",
        "X-Requested-With",
    )
    expose_headers: tuple[str, ...] = ("X-Request-ID", "Retry-After")
    max_age: int = 600
    allow_http_origins: bool = False  # apenas para desenvolvimento local
    reject_disallowed_unsafe: bool = True

    def __post_init__(self) -> None:
        origins: set[str] = set()
        for raw in self.allowed_origins:
            if raw.strip() == "*":
                raise ValueError("CORS: '*' é proibido (a API usa credenciais).")
            norm = normalize_origin(raw, strict_config=True)
            if norm is None:
                raise ValueError(f"CORS: origem inválida na configuração: {raw!r}")
            if norm.startswith("http://") and not self.allow_http_origins:
                raise ValueError(f"CORS: origem http não permitida em produção: {raw!r}")
            origins.add(norm)
        object.__setattr__(self, "allowed_origins", frozenset(origins))

        for m in self.allowed_methods:
            if not _HEADER_TOKEN.match(m) or m != m.upper():
                raise ValueError(f"CORS: método inválido: {m!r}")
        for h in (*self.allowed_headers, *self.expose_headers):
            if h == "*" or not _HEADER_TOKEN.match(h):
                raise ValueError(f"CORS: header inválido (curinga não vale com credenciais): {h!r}")
        if not 0 <= self.max_age <= _MAX_PREFLIGHT_AGE:
            raise ValueError("CORS: max_age fora do intervalo permitido.")
        if not self.allowed_origins and self.origin_validator is None:
            raise ValueError("CORS: nenhuma origem configurada.")


class CORSMiddleware:
    """Middleware ASGI. Deve ser o mais externo da pilha, para que respostas de
    erro (4xx/5xx geradas por outros middlewares) também carreguem os headers."""

    def __init__(self, app, config: CorsConfig) -> None:
        self.app = app
        self.cfg = config
        self._methods = frozenset(config.allowed_methods)
        self._headers_lc = frozenset(h.lower() for h in config.allowed_headers)
        self._allow_methods_hdr = ", ".join(config.allowed_methods).encode("latin-1")
        self._allow_headers_hdr = ", ".join(config.allowed_headers).encode("latin-1")
        self._expose_hdr = ", ".join(config.expose_headers).encode("latin-1")

    # ------------------------------------------------------------------ ASGI
    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":  # lifespan / websocket seguem direto
            await self.app(scope, receive, send)
            return

        headers = scope.get("headers", [])
        origin_values = [v for k, v in headers if k == b"origin"]
        method = scope["method"].upper()

        # Sem Origin: não é requisição cross-origin de navegador.
        if not origin_values:
            await self.app(scope, receive, self._with_vary_only(send))
            return

        # Múltiplos headers Origin são ambíguos: negar.
        origin = self._decode_origin(origin_values[0]) if len(origin_values) == 1 else None
        allowed = origin is not None and await self._is_allowed(origin)

        if self._is_preflight(method, headers):
            if not allowed:
                self._log_denied(origin_values[0], "preflight")
            await self._handle_preflight(send, origin if allowed else None, headers)
            return

        if not allowed:
            self._log_denied(origin_values[0], method)
            if self.cfg.reject_disallowed_unsafe and method not in SAFE_METHODS:
                await self._respond(send, 403, b"Origin not allowed")
                return
            # Métodos seguros: segue sem headers CORS; o navegador bloqueia a leitura.
            await self.app(scope, receive, self._with_vary_only(send))
            return

        await self.app(scope, receive, self._with_cors(send, origin))

    # ------------------------------------------------------------- validação
    @staticmethod
    def _decode_origin(raw: bytes) -> Optional[str]:
        try:
            return normalize_origin(raw.decode("ascii"))
        except UnicodeDecodeError:
            return None

    async def _is_allowed(self, origin: str) -> bool:
        if origin.startswith("http://") and not self.cfg.allow_http_origins:
            return False
        if origin in self.cfg.allowed_origins:
            return True
        if self.cfg.origin_validator is None:
            return False
        try:
            return bool(await self.cfg.origin_validator(origin))
        except Exception:  # falha fechada
            logger.exception("Falha no validador dinâmico de origem CORS")
            return False

    @staticmethod
    def _is_preflight(method: str, headers) -> bool:
        return method == "OPTIONS" and any(k == b"access-control-request-method" for k, _ in headers)

    @staticmethod
    def _log_denied(raw: bytes, context: str) -> None:
        safe = raw[:100].decode("ascii", errors="replace")
        safe = "".join(c if c.isprintable() else "?" for c in safe)
        logger.warning("CORS negado (%s): origin=%r", context, safe)

    # ------------------------------------------------------------- preflight
    async def _handle_preflight(self, send, origin: Optional[str], headers) -> None:
        if origin is None:
            await self._respond(send, 403, b"Origin not allowed")
            return

        req_method = self._header(headers, b"access-control-request-method").strip().upper()
        if req_method not in self._methods:
            await self._respond(send, 403, b"Method not allowed")
            return

        req_headers_raw = self._header(headers, b"access-control-request-headers")
        requested = [h.strip().lower() for h in req_headers_raw.split(",") if h.strip()]
        if any(h not in self._headers_lc for h in requested):
            await self._respond(send, 403, b"Header not allowed")
            return

        resp = [
            (b"access-control-allow-origin", origin.encode("ascii")),
            (b"access-control-allow-credentials", b"true"),
            (b"access-control-allow-methods", self._allow_methods_hdr),
            (b"access-control-allow-headers", self._allow_headers_hdr),
            (b"access-control-max-age", str(self.cfg.max_age).encode("ascii")),
            (
                b"vary",
                b"Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
            ),
            (b"content-length", b"0"),
        ]
        await send({"type": "http.response.start", "status": 204, "headers": resp})
        await send({"type": "http.response.body", "body": b""})

    @staticmethod
    def _header(headers, name: bytes) -> str:
        for k, v in headers:
            if k == name:
                return v.decode("latin-1")
        return ""

    @staticmethod
    async def _respond(send, status: int, body: bytes) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"vary", b"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    # ------------------------------------------------- resposta da aplicação
    @staticmethod
    def _merge_vary(existing: list[bytes], token: bytes = b"Origin") -> bytes:
        values: list[bytes] = []
        for item in existing:
            values.extend(p.strip() for p in item.split(b",") if p.strip())
        if b"*" in values:
            return b"*"
        if token.lower() not in (v.lower() for v in values):
            values.append(token)
        return b", ".join(values)

    def _rewrite(self, message: dict, extra: list[tuple[bytes, bytes]]) -> dict:
        hdrs = list(message.get("headers", []))
        vary = [v for k, v in hdrs if k.lower() == b"vary"]
        kept = [
            (k, v)
            for k, v in hdrs
            if k.lower() not in _CORS_RESPONSE_HEADERS and k.lower() != b"vary"
        ]
        kept.extend(extra)
        kept.append((b"vary", self._merge_vary(vary)))
        return {**message, "headers": kept}

    def _with_vary_only(self, send):
        async def wrapper(message):
            if message["type"] == "http.response.start":
                message = self._rewrite(message, [])
            await send(message)

        return wrapper

    def _with_cors(self, send, origin: str):
        extra = [
            (b"access-control-allow-origin", origin.encode("ascii")),
            (b"access-control-allow-credentials", b"true"),
        ]
        if self._expose_hdr:
            extra.append((b"access-control-expose-headers", self._expose_hdr))

        async def wrapper(message):
            if message["type"] == "http.response.start":
                message = self._rewrite(message, extra)
            await send(message)

        return wrapper


# --------------------------------------------------------------------------
# Exemplo de uso (FastAPI/Starlette)
# --------------------------------------------------------------------------
#
#   from fastapi import FastAPI
#
#   async def tenant_origin_validator(origin: str) -> bool:
#       # Consulte (com cache curto) apenas domínios cadastrados E verificados
#       # pelos tenants (ex.: validação por registro DNS TXT), para evitar que
#       # um tenant autorize domínios que não controla.
#       return await repo.is_verified_tenant_origin(origin)
#
#   app = FastAPI()
#   ...rotas...
#   app = CORSMiddleware(
#       app,
#       CorsConfig(
#           allowed_origins=["https://app.plataforma.com.br"],
#           origin_validator=tenant_origin_validator,
#       ),
#   )   # envolver por último => middleware mais externo
#
# Requisitos complementares (fora do escopo deste middleware):
#   * Cookie de sessão: HttpOnly; Secure; SameSite=None (necessário para uso
#     cross-site; navegadores com bloqueio de cookies de terceiros podem exigir
#     CHIPS/"Partitioned" ou domínio irmão).
#   * Validar o token CSRF (X-CSRF-Token) em toda requisição não segura.
#   * Aplicar autorização por tenant (tenant_id da sessão) em cada consulta.
#   * Rate limiting e HTTPS/HSTS na borda.