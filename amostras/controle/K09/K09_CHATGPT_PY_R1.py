from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from typing import Any, Iterable

from starlette.types import ASGIApp, Message, Receive, Scope, Send


logger = logging.getLogger("security.auth")


# Campos que podem ser registrados.
#
# A lista deve ser explicitamente permitida (allowlist), em vez de tentar
# descobrir dinamicamente quais campos são "seguros".
SAFE_REQUEST_FIELDS = frozenset(
    {
        "username",
        "email",
        "login",
        "tenant_id",
    }
)

# Nunca registrar esses campos, mesmo que algum deles seja posteriormente
# adicionado por engano à allowlist.
SENSITIVE_FIELDS = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "current_password",
        "new_password",
        "password_confirmation",
        "access_token",
        "refresh_token",
        "token",
        "api_key",
        "secret",
        "client_secret",
        "authorization",
        "cookie",
        "session",
        "session_id",
        "csrf_token",
        "mfa_code",
        "otp",
        "code",
    }
)

MAX_BODY_BYTES = 16 * 1024
MAX_LOG_VALUE_LENGTH = 256


def _sanitize_value(value: Any) -> Any:
    """
    Remove/limita dados antes que cheguem ao logger.

    Não se deve confiar no conteúdo recebido pelo cliente.
    """
    if value is None:
        return None

    if isinstance(value, str):
        # Evita valores gigantes e reduz possibilidades de abuso contra
        # sistemas consumidores de logs.
        value = value[:MAX_LOG_VALUE_LENGTH]

        # Remove caracteres de controle que podem ser usados para
        # manipulação visual/injeção em determinados destinos de log.
        return "".join(
            char
            for char in value
            if char.isprintable() and char not in "\r\n\t"
        )

    if isinstance(value, (int, float, bool)):
        return value

    return str(value)[:MAX_LOG_VALUE_LENGTH]


def _extract_safe_fields(body: bytes) -> dict[str, Any]:
    """
    Extrai somente campos explicitamente permitidos.

    Se o corpo não for JSON ou não puder ser processado, nenhum campo do
    corpo será registrado.
    """
    if not body or len(body) > MAX_BODY_BYTES:
        return {}

    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}

    if not isinstance(payload, dict):
        return {}

    result: dict[str, Any] = {}

    for field in SAFE_REQUEST_FIELDS:
        if field not in payload:
            continue

        # Defesa adicional caso um campo sensível seja incluído
        # acidentalmente na allowlist no futuro.
        if field.lower() in SENSITIVE_FIELDS:
            continue

        result[field] = _sanitize_value(payload[field])

    return result


def _hash_identifier(value: str | None) -> str | None:
    """
    Gera um identificador pseudonimizado para facilitar correlação
    sem armazenar diretamente determinado identificador.

    O segredo usado no HMAC deve ser preferencialmente fornecido por
    configuração/secret manager em produção.
    """
    if not value:
        return None

    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:16]


class FailedAuthenticationLoggingMiddleware:
    """
    Middleware ASGI para registrar tentativas de autenticação malsucedidas.

    Importante:
    - O middleware NÃO determina sozinho se o login falhou.
    - Ele observa a resposta de endpoints de autenticação.
    - O endpoint de autenticação deve estar configurado em
      authentication_paths.
    """

    def __init__(
        self,
        app: ASGIApp,
        authentication_paths: Iterable[str] = (
            "/login",
            "/auth/login",
            "/api/auth/login",
        ),
    ) -> None:
        self.app = app
        self.authentication_paths = frozenset(authentication_paths)

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:

        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # Só intercepta endpoints de autenticação.
        if path not in self.authentication_paths:
            await self.app(scope, receive, send)
            return

        request_body = bytearray()
        request_too_large = False

        async def receive_wrapper() -> Message:
            nonlocal request_too_large

            message = await receive()

            if message["type"] == "http.request":
                body = message.get("body", b"")

                if len(request_body) + len(body) <= MAX_BODY_BYTES:
                    request_body.extend(body)
                else:
                    request_too_large = True

            return message

        response_status: int | None = None
        started_at = time.monotonic()

        async def send_wrapper(message: Message) -> None:
            nonlocal response_status

            if message["type"] == "http.response.start":
                response_status = int(message["status"])

            await send(message)

        try:
            await self.app(
                scope,
                receive_wrapper,
                send_wrapper,
            )

        except Exception:
            # Não registrar stack trace contendo request data.
            logger.exception(
                "Authentication endpoint raised an exception",
                extra={
                    "event": "authentication_error",
                    "request_id": self._request_id(scope),
                    "path": path,
                    "method": scope.get("method"),
                },
            )
            raise

        duration_ms = round(
            (time.monotonic() - started_at) * 1000,
            2,
        )

        # Neste exemplo, 401 representa autenticação malsucedida.
        #
        # Dependendo da aplicação, 403 pode representar autorização
        # recusada e NÃO deve automaticamente ser tratado como falha
        # de autenticação.
        if response_status != 401:
            return

        headers = self._headers(scope)

        client_ip = self._client_ip(scope)

        tenant_id = self._extract_tenant_id(
            request_body=bytes(request_body),
            headers=headers,
        )

        safe_fields = _extract_safe_fields(bytes(request_body))

        event = {
            "event": "authentication_failure",
            "event_version": 1,
            "request_id": self._request_id(scope),
            "timestamp_unix": time.time(),
            "method": scope.get("method"),
            "path": path,
            "status": response_status,
            "duration_ms": duration_ms,

            # Para facilitar investigação sem armazenar o IP em claro,
            # pseudonimize-o antes de enviá-lo ao log.
            "source_ip_hash": _hash_identifier(client_ip),

            "user_agent": _sanitize_value(
                headers.get("user-agent")
            ),

            "tenant_id": _sanitize_value(tenant_id),

            # Somente campos explicitamente permitidos.
            "request_fields": safe_fields,

            # Indica que o corpo não pôde ser completamente observado.
            # Não registra seu conteúdo.
            "request_body_truncated": request_too_large,
        }

        logger.warning(
            "Authentication attempt failed",
            extra={
                "security_event": event,
            },
        )

    @staticmethod
    def _headers(scope: Scope) -> dict[str, str]:
        result: dict[str, str] = {}

        for key, value in scope.get("headers", []):
            try:
                result[
                    key.decode("latin-1").lower()
                ] = value.decode("latin-1")
            except UnicodeDecodeError:
                continue

        return result

    @staticmethod
    def _client_ip(scope: Scope) -> str | None:
        """
        Não confia cegamente em X-Forwarded-For.

        Em produção, o IP real deve ser determinado pelo proxy reverso
        confiável (load balancer/API gateway) e sua configuração.
        """
        client = scope.get("client")

        if not client:
            return None

        return str(client[0])

    @staticmethod
    def _request_id(scope: Scope) -> str:
        """
        Usa o request ID existente somente se ele tiver sido previamente
        validado pelo gateway/middleware de confiança.

        Caso contrário, gera um novo identificador.
        """
        for key, value in scope.get("headers", []):
            if key.lower() == b"x-request-id":
                try:
                    candidate = value.decode("ascii")

                    # Limite simples para evitar abusos contra o sistema
                    # de logging.
                    if 1 <= len(candidate) <= 64:
                        return candidate
                except UnicodeDecodeError:
                    pass

        return str(uuid.uuid4())

    @staticmethod
    def _extract_tenant_id(
        request_body: bytes,
        headers: dict[str, str],
    ) -> str | None:
        """
        Tenant deve ser obtido de uma fonte confiável.

        Se o tenant vier diretamente do usuário, ele não deve ser usado
        para autorização. O ideal é que seja resolvido pelo domínio,
        API gateway ou pelo serviço de autenticação.
        """

        # Exemplo: tenant resolvido previamente por infraestrutura confiável.
        trusted_tenant = headers.get("x-authenticated-tenant")

        if trusted_tenant:
            return trusted_tenant

        # Fallback apenas para observabilidade; não usar esse valor
        # para autorização.
        try:
            payload = json.loads(request_body)

            if isinstance(payload, dict):
                tenant_id = payload.get("tenant_id")

                if isinstance(tenant_id, str):
                    return tenant_id[:MAX_LOG_VALUE_LENGTH]

        except (UnicodeDecodeError, json.JSONDecodeError):
            pass

        return None
