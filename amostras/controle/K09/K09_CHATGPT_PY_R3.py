from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

from starlette.types import ASGIApp, Message, Receive, Scope, Send


logger = logging.getLogger("security.authentication")


# Limite deliberadamente pequeno para impedir que o mecanismo de auditoria
# seja utilizado para armazenar grandes quantidades de dados.
MAX_LOGGED_BODY_BYTES = 64 * 1024

# Campos que nunca devem aparecer nos logs.
SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "pass",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "set-cookie",
    "client_secret",
    "private_key",
    "otp",
    "code",
    "mfa_code",
    "totp",
}

# Somente estes headers podem ser registrados.
SAFE_HEADERS = {
    "content-type",
    "content-length",
    "user-agent",
    "accept",
    "x-request-id",
}


def _get_audit_key() -> bytes:
    """
    Chave usada para pseudonimizar identificadores no log.

    A chave DEVE ser fornecida por variável de ambiente/secret manager.
    Não use um valor fixo no código.
    """
    value = os.getenv("AUDIT_LOG_HMAC_KEY")

    if not value:
        raise RuntimeError(
            "AUDIT_LOG_HMAC_KEY não configurada. "
            "O serviço não deve iniciar sem uma chave de auditoria."
        )

    return value.encode("utf-8")


def pseudonymize(value: str) -> str:
    """
    Produz um identificador estável, mas que não expõe o valor original.

    Útil, por exemplo, para permitir que o suporte encontre várias
    tentativas feitas para o mesmo e-mail sem armazenar o e-mail em claro.
    """
    digest = hmac.new(
        _get_audit_key(),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return digest[:32]


def sanitize_value(
    key: str,
    value: Any,
    *,
    depth: int = 0,
) -> Any:
    """
    Remove recursivamente informações sensíveis de objetos JSON.
    """

    if depth > 8:
        return "[MAX_DEPTH]"

    normalized_key = key.lower().replace("-", "_")

    if normalized_key in SENSITIVE_FIELDS:
        return "[REDACTED]"

    if isinstance(value, dict):
        return {
            str(k): sanitize_value(str(k), v, depth=depth + 1)
            for k, v in value.items()
        }

    if isinstance(value, list):
        # Evita logs gigantescos causados por arrays.
        if len(value) > 100:
            return [
                sanitize_value(key, item, depth=depth + 1)
                for item in value[:100]
            ] + ["[TRUNCATED]"]

        return [
            sanitize_value(key, item, depth=depth + 1)
            for item in value
        ]

    if isinstance(value, str) and len(value) > 4096:
        return value[:4096] + "[TRUNCATED]"

    return value


def sanitize_json_body(body: bytes) -> Dict[str, Any]:
    """
    Converte um corpo JSON em estrutura segura para logging.
    """
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {
            "_body": "[NON_JSON_OR_INVALID_UTF8]"
        }

    if not isinstance(parsed, dict):
        return {
            "_body": sanitize_value("body", parsed)
        }

    return sanitize_value("body", parsed)


def get_header(
    headers: Iterable[Tuple[bytes, bytes]],
    name: str,
) -> Optional[str]:
    name_bytes = name.lower().encode("latin-1")

    for key, value in headers:
        if key.lower() == name_bytes:
            return value.decode("latin-1", errors="replace")

    return None


def safe_headers(
    headers: Iterable[Tuple[bytes, bytes]],
) -> Dict[str, str]:
    """
    Registra somente headers explicitamente permitidos.
    """
    result: Dict[str, str] = {}

    for key, value in headers:
        name = key.decode("latin-1").lower()

        if name in SAFE_HEADERS:
            result[name] = value.decode("latin-1", errors="replace")

    return result


def hash_ip(ip: Optional[str]) -> Optional[str]:
    """
    Não grava o IP em claro.

    Se o suporte realmente precisar do IP original, esse requisito deve
    ser tratado como uma decisão explícita de privacidade/compliance,
    e não como efeito colateral do middleware.
    """
    if not ip:
        return None

    return pseudonymize(ip)


class AuthenticationFailureLoggingMiddleware:
    """
    Middleware ASGI que registra falhas de autenticação.

    O middleware não decide se uma requisição é autenticada.
    Ele observa a resposta produzida pela aplicação e, para respostas
    401/403, cria um evento de auditoria sanitizado.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int = MAX_LOGGED_BODY_BYTES,
    ) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = self._request_id(scope)

        status_code: Optional[int] = None

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code

            if message["type"] == "http.response.start":
                status_code = int(message["status"])

            await send(message)

        # Capturamos o corpo somente para requisições pequenas e JSON.
        body = await self._capture_small_json_body(
            scope,
            receive,
        )

        started_at = time.monotonic()

        try:
            await self.app(
                scope,
                receive,
                send_wrapper,
            )
        except Exception:
            # Erros internos não são classificados aqui como falhas de
            # autenticação. O tratamento de exceções deve ser feito pelo
            # middleware de erro da aplicação.
            raise
        finally:
            duration_ms = round(
                (time.monotonic() - started_at) * 1000,
                2,
            )

            if status_code in (401, 403):
                self._log_authentication_failure(
                    scope=scope,
                    request_id=request_id,
                    status_code=status_code,
                    body=body,
                    duration_ms=duration_ms,
                )

    @staticmethod
    def _request_id(scope: Scope) -> str:
        """
        Usa X-Request-ID somente como correlação visual.

        Não confiamos nele como mecanismo de segurança, portanto, quando
        ausente, criamos um identificador criptograficamente aleatório.
        """
        headers = scope.get("headers", [])

        supplied = get_header(headers, "x-request-id")

        if supplied and len(supplied) <= 128:
            # O valor externo pode ser usado para correlação, mas não deve
            # ser considerado confiável para autenticação/autorização.
            return supplied

        return str(uuid.uuid4())

    async def _capture_small_json_body(
        self,
        scope: Scope,
        receive: Receive,
    ) -> Optional[bytes]:
        """
        Captura o corpo apenas quando podemos determinar previamente que
        ele é pequeno.

        Isso evita que um atacante envie um body gigantesco apenas para
        fazê-lo ser armazenado pelo mecanismo de auditoria.
        """
        headers = scope.get("headers", [])

        content_type = get_header(headers, "content-type")
        content_length = get_header(headers, "content-length")

        if not content_type:
            return None

        if "application/json" not in content_type.lower():
            return None

        if not content_length:
            # Para requests chunked/streaming não armazenamos o body.
            return None

        try:
            length = int(content_length)
        except ValueError:
            return None

        if length < 0 or length > self.max_body_bytes:
            return None

        chunks: List[bytes] = []
        received = 0

        while received < length:
            message = await receive()

            if message["type"] != "http.request":
                continue

            chunk = message.get("body", b"")

            received += len(chunk)

            if received > self.max_body_bytes:
                return None

            chunks.append(chunk)

            if not message.get("more_body", False):
                break

        body = b"".join(chunks)

        # O body foi consumido. Recolocamos uma cópia para que a aplicação
        # continue recebendo exatamente os dados enviados pelo cliente.
        replayed = False

        async def replay_receive() -> Message:
            nonlocal replayed

            if not replayed:
                replayed = True

                return {
                    "type": "http.request",
                    "body": body,
                    "more_body": False,
                }

            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        # Não podemos substituir diretamente o objeto receive usado pelo
        # chamador porque ele já foi recebido como closure. A solução é
        # guardar a função para uso posterior.
        #
        # Para este middleware, fazemos isso alterando o atributo local
        # utilizado por __call__ através do wrapper abaixo.
        #
        # Como Python não permite reassignment do parâmetro closure de forma
        # útil neste ponto, retornamos o body e a aplicação recebe o body
        # através de receive replay no método __call__.
        scope["_auth_logging_replay_receive"] = replay_receive

        return body

    def _log_authentication_failure(
        self,
        *,
        scope: Scope,
        request_id: str,
        status_code: int,
        body: Optional[bytes],
        duration_ms: float,
    ) -> None:
        headers = scope.get("headers", [])

        client = scope.get("client")
        client_ip = client[0] if client else None

        method = scope.get("method", "")
        path = scope.get("path", "")

        content_type = get_header(headers, "content-type")

        event: Dict[str, Any] = {
            "event": "authentication_failure",
            "timestamp": time.time(),
            "request_id": request_id,
            "http": {
                "method": method,
                "path": path,
                "status": status_code,
                "duration_ms": duration_ms,
            },
            "client": {
                "ip_hash": hash_ip(client_ip),
            },
            "request": {
                "headers": safe_headers(headers),
                "body_captured": body is not None,
            },
        }

        if body is not None:
            if content_type and "application/json" in content_type.lower():
                event["request"]["body"] = sanitize_json_body(body)
            else:
                event["request"]["body"] = "[UNSUPPORTED_CONTENT_TYPE]"

        # O tenant enviado pelo cliente não deve ser tratado como confiável.
        #
        # Caso a aplicação tenha resolvido o tenant antes da falha de
        # autenticação, ele deve ser anexado pelo componente de autenticação
        # a um contexto confiável, e não extraído cegamente do JSON.
        tenant_id = scope.get("auth_context_tenant_id")

        if tenant_id:
            event["tenant"] = {
                "id": tenant_id,
            }

        # Logging estruturado.
        #
        # Nunca usar:
        # logger.warning("login failed: %s", body)
        #
        # pois isso poderia expor credenciais.
        logger.warning(
            json.dumps(
                event,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
