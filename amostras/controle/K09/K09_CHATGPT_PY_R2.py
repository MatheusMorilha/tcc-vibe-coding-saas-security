import json
import logging
import re
from typing import Any, Iterable, Mapping, Optional


logger = logging.getLogger("security.authentication")


# Campos que nunca devem aparecer no log.
SENSITIVE_FIELD_NAMES = {
    "password",
    "passwd",
    "pass",
    "current_password",
    "new_password",
    "confirm_password",
    "password_confirmation",
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "set-cookie",
    "private_key",
}

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}

# Limita o tamanho do conteúdo que poderá chegar ao log.
MAX_LOG_BODY_BYTES = 8 * 1024
MAX_LOG_VALUE_LENGTH = 512


def _normalize_name(name: str) -> str:
    """
    Normaliza nomes para comparação segura.
    Ex.: 'clientPassword' -> 'clientpassword'
    """
    return re.sub(r"[^a-z0-9]", "", name.lower())


NORMALIZED_SENSITIVE_FIELDS = {
    _normalize_name(name)
    for name in SENSITIVE_FIELD_NAMES
}


def _is_sensitive_field(name: str) -> bool:
    normalized = _normalize_name(name)

    if normalized in NORMALIZED_SENSITIVE_FIELDS:
        return True

    # Também protege variações como:
    # user_password, password_hash, authorization_token etc.
    sensitive_fragments = (
        "password",
        "passwd",
        "passcode",
        "secret",
        "token",
        "apikey",
        "privatekey",
        "authorization",
    )

    return any(fragment in normalized for fragment in sensitive_fragments)


def _redact(value: Any, field_name: Optional[str] = None) -> Any:
    """
    Remove/redige dados sensíveis recursivamente.
    """
    if field_name and _is_sensitive_field(field_name):
        return "[REDACTED]"

    if isinstance(value, Mapping):
        return {
            str(key): _redact(item, str(key))
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            _redact(item)
            for item in value
        ]

    if isinstance(value, tuple):
        return [
            _redact(item)
            for item in value
        ]

    if isinstance(value, bytes):
        return _truncate(value.decode("utf-8", errors="replace"))

    if isinstance(value, str):
        return _truncate(value)

    return value


def _truncate(value: str) -> str:
    if len(value) <= MAX_LOG_VALUE_LENGTH:
        return value

    return value[:MAX_LOG_VALUE_LENGTH] + "...[TRUNCATED]"


def _sanitize_headers(
    headers: Iterable[tuple[bytes, bytes]],
) -> dict[str, str]:
    """
    Copia headers sem expor credenciais ou cookies.
    """
    result: dict[str, str] = {}

    for raw_name, raw_value in headers:
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1", errors="replace")

        if name in SENSITIVE_HEADER_NAMES:
            result[name] = "[REDACTED]"
        else:
            result[name] = _truncate(value)

    return result


async def _read_body(receive) -> tuple[bytes, Any]:
    """
    Lê o body ASGI e devolve:
      - bytes originais
      - versão decodificada para logging

    O body original é limitado para impedir que uma requisição
    extremamente grande seja colocada na memória.
    """
    chunks: list[bytes] = []
    total_size = 0
    more_body = True

    while more_body:
        message = await receive()

        if message["type"] != "http.request":
            continue

        chunk = message.get("body", b"")
        more_body = message.get("more_body", False)

        if chunk:
            remaining = MAX_LOG_BODY_BYTES - total_size

            if remaining > 0:
                chunks.append(chunk[:remaining])
                total_size += min(len(chunk), remaining)

    body = b"".join(chunks)

    # O body utilizado pela aplicação precisa continuar disponível.
    # O middleware guarda somente até MAX_LOG_BODY_BYTES para logging.
    return body, body


def _decode_body(body: bytes, content_type: str) -> Any:
    """
    Decodifica formatos comuns de autenticação.
    Nunca lança exceção para conteúdo inválido.
    """
    if not body:
        return None

    content_type = content_type.lower()

    if "application/json" in content_type:
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return "[INVALID_JSON]"

    if (
        "application/x-www-form-urlencoded" in content_type
        or "multipart/form-data" in content_type
    ):
        # Não fazemos parsing de multipart aqui para evitar que
        # arquivos e grandes payloads sejam carregados no log.
        if "multipart/form-data" in content_type:
            return "[MULTIPART_BODY_OMITTED]"

        try:
            from urllib.parse import parse_qs

            parsed = parse_qs(
                body.decode("utf-8", errors="replace"),
                keep_blank_values=True,
            )

            return {
                key: values[0] if len(values) == 1 else values
                for key, values in parsed.items()
            }

        except Exception:
            return "[INVALID_FORM_BODY]"

    return "[BODY_OMITTED]"


def _client_ip(scope: dict) -> Optional[str]:
    """
    Obtém o IP diretamente da conexão.
    Não confia em X-Forwarded-For sem configuração explícita
    de proxy confiável.
    """
    client = scope.get("client")

    if not client:
        return None

    return client[0]


def _tenant_id(scope: dict) -> Optional[str]:
    """
    Recupera o tenant que já tenha sido resolvido pelo mecanismo
    de autenticação/autorização da aplicação.

    Não devemos aceitar tenant_id enviado livremente pelo cliente
    como identidade confiável.
    """
    state = scope.get("state", {})

    tenant = state.get("tenant")

    if isinstance(tenant, dict):
        return tenant.get("id")

    if tenant is not None:
        return str(tenant)

    return None


class FailedAuthenticationLoggingMiddleware:
    """
    Middleware ASGI que registra tentativas de autenticação
    malsucedidas sem armazenar credenciais ou segredos.

    Por padrão, considera 401 e 403 como eventos de autenticação/
    autorização que merecem investigação.

    Em uma aplicação real, é preferível marcar explicitamente as
    rotas de autenticação para evitar registrar respostas 403 que
    não estejam relacionadas ao login.
    """

    AUTH_PATHS = {
        "/login",
        "/auth/login",
        "/api/login",
        "/api/auth/login",
        "/token",
        "/auth/token",
    }

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET").upper()

        # Registra somente endpoints conhecidos de autenticação.
        # Isso reduz ruído e evita registrar dados de endpoints
        # empresariais que retornem 401/403.
        should_log_auth_failure = (
            method in {"POST", "PUT", "PATCH"}
            and path in self.AUTH_PATHS
        )

        if not should_log_auth_failure:
            await self.app(scope, receive, send)
            return

        request_body, _ = await _read_body(receive)

        content_type = ""
        for name, value in scope.get("headers", []):
            if name.lower() == b"content-type":
                content_type = value.decode(
                    "latin-1",
                    errors="replace",
                )
                break

        # O receive original foi consumido. Criamos um receive
        # que entrega o body novamente para a aplicação.
        body_sent = False

        async def replay_receive():
            nonlocal body_sent

            if not body_sent:
                body_sent = True

                return {
                    "type": "http.request",
                    "body": request_body,
                    "more_body": False,
                }

            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        response_status: Optional[int] = None

        async def capture_send(message):
            nonlocal response_status

            if message["type"] == "http.response.start":
                response_status = message["status"]

            await send(message)

        await self.app(
            scope,
            replay_receive,
            capture_send,
        )

        if response_status not in {401, 403}:
            return

        raw_payload = _decode_body(
            request_body,
            content_type,
        )

        safe_payload = _redact(raw_payload)

        headers = _sanitize_headers(
            scope.get("headers", [])
        )

        event = {
            "event": "authentication_failure",
            "method": method,
            "path": path,
            "status": response_status,
            "tenant_id": _tenant_id(scope),
            "client_ip": _client_ip(scope),
            "user_agent": headers.get("user-agent"),
            "request_id": (
                headers.get("x-request-id")
                or headers.get("x-correlation-id")
            ),
            "payload": safe_payload,
        }

        logger.warning(
            "Failed authentication attempt",
            extra={
                "security_event": event,
            },
        )
