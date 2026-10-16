import json
import logging
import re
from typing import Any, Dict, Set
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Configuração de logger estruturado
logger = logging.getLogger("security.auth_audit")
logger.setLevel(logging.INFO)

# Chaves sensíveis que NUNCA devem ser registradas em texto legível
SENSITIVE_KEYS: Set[str] = {
    "password", "senha", "secret", "token", "access_token",
    "refresh_token", "api_key", "pin", "mfa_code", "totp"
}

MAX_BODY_LOG_SIZE = 16_384  # 16 KB para prevenir DoS via consumo de memória


def sanitize_value(val: Any) -> Any:
    """Higieniza quebras de linha para evitar Log Injection (CWE-117)."""
    if isinstance(val, str):
        return re.sub(r"[\r\n]", "", val)
    return val


def redact_sensitive_data(payload: Any) -> Any:
    """
    Percorre recursivamente dicionários e listas mascarando credenciais sensíveis.
    """
    if isinstance(payload, dict):
        sanitized = {}
        for key, value in payload.items():
            clean_key = sanitize_value(str(key))
            if clean_key.lower() in SENSITIVE_KEYS:
                sanitized[clean_key] = "[REDACTED]"
            else:
                sanitized[clean_key] = redact_sensitive_data(value)
        return sanitized
    elif isinstance(payload, list):
        return [redact_sensitive_data(item) for item in payload]
    else:
        return sanitize_value(payload)


class FailedAuthLoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, auth_routes: Set[str] = None):
        super().__init__(app)
        # Rotas críticas de autenticação a serem monitoradas
        self.auth_routes = auth_routes or {
            "/api/v1/auth/login",
            "/api/v1/auth/token",
            "/api/v1/auth/mfa/verify"
        }

    async def dispatch(self, request: Request, call_next) -> Response:
        # Se não for uma rota de autenticação nem método POST, segue fluxo padrão
        if request.url.path not in self.auth_routes or request.method != "POST":
            return await call_next(request)

        # 1. Leitura do corpo sem consumir a stream da aplicação
        body_bytes = await request.body()

        # 2. Executa a requisição
        response = await call_next(request)

        # 3. Intercepta falhas de autenticação (401 Unauthorized ou 403 Forbidden)
        if response.status_code in {401, 403}:
            await self._log_failed_attempt(request, body_bytes, response.status_code)

        return response

    async def _log_failed_attempt(self, request: Request, body_bytes: bytes, status_code: int):
        # Extração de identificadores multilocatários e de rede
        tenant_id = (
            request.headers.get("x-tenant-id")
            or request.headers.get("host", "").split(".")[0]
            or "unknown_tenant"
        )
        client_ip = request.client.host if request.client else "unknown_ip"
        user_agent = sanitize_value(request.headers.get("user-agent", "unknown"))

        # Parsing e higienização do corpo da requisição
        parsed_payload: Dict[str, Any] = {}
        if body_bytes:
            if len(body_bytes) > MAX_BODY_LOG_SIZE:
                parsed_payload = {"_error": "Payload exceeds maximum log limit"}
            else:
                try:
                    raw_json = json.loads(body_bytes.decode("utf-8", errors="replace"))
                    parsed_payload = redact_sensitive_data(raw_json)
                except Exception:
                    parsed_payload = {"_error": "Payload is not valid UTF-8 JSON"}

        # Montagem do evento de log de auditoria estruturado
        audit_entry = {
            "event": "FAILED_AUTHENTICATION_ATTEMPT",
            "tenant_id": sanitize_value(tenant_id),
            "ip_address": sanitize_value(client_ip),
            "user_agent": user_agent,
            "path": request.url.path,
            "status_code": status_code,
            "submitted_data": parsed_payload
        }

        # Emissão como JSON estruturado na saída padrão / coletor de logs
        logger.warning(json.dumps(audit_entry))

from fastapi import FastAPI

app = FastAPI()

app.add_middleware(
    FailedAuthLoggingMiddleware,
    auth_routes={"/api/v1/auth/login", "/api/v1/auth/token"}
)