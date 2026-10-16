import json
import logging
import re
from typing import Any, Dict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Configuração de logger estruturado
logger = logging.getLogger("security.auth.audit")
logger.setLevel(logging.WARNING)

# Campos sensíveis que NUNCA devem ser logados em texto claro (OWASP Data Protection)
SENSITIVE_KEYS = {
    "password", "senha", "pass", "token", "access_token",
    "refresh_token", "secret", "api_key", "authorization",
    "credit_card", "cvv"
}

# Rotas de autenticação monitoradas
AUTH_ENDPOINTS = {
    "/api/v1/auth/login",
    "/api/v1/auth/token",
    "/api/v1/auth/authenticate"
}

def sanitize_payload(data: Any) -> Any:
    """
    Higieniza recursivamente os dados enviados no corpo da requisição.
    Substitui senhas e segredos por máscaras de segurança.
    """
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            if str(key).lower() in SENSITIVE_KEYS:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = sanitize_payload(value)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_payload(item) for item in data]
    return data

def sanitize_string(value: str) -> str:
    """
    Remove quebras de linha e caracteres de controle para evitar Log Injection (CRLF).
    """
    if not isinstance(value, str):
        return str(value)
    return re.sub(r"[\r\n\t]", " ", value).strip()

def get_client_ip(request: Request) -> str:
    """
    Obtém o IP real do cliente tratando proxies/load balancers reversos com segurança.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # Pega o primeiro IP da cadeia (cliente original)
        return sanitize_string(forwarded.split(",")[0].strip())
    return sanitize_string(request.client.host if request.client else "unknown")

class FailedAuthAuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Processa apenas rotas de autenticação via POST/PUT
        if request.url.path not in AUTH_ENDPOINTS or request.method not in ("POST", "PUT"):
            return await call_next(request)

        # Lê e armazena o corpo da requisição sem esgotar o stream para a rota subsequente
        body_bytes = await request.body()

        # Reconstrói a função receive para que a rota final ainda consiga ler o body
        async def receive():
            return {"type": "http.request", "body": body_bytes}

        request_with_cached_body = Request(request.scope, receive=receive)

        # Executa a requisição até a camada de aplicação
        response = await call_next(request_with_cached_body)

        # 401 (Unauthorized) ou 403 (Forbidden) indicam falha de autenticação/acesso
        if response.status_code in (401, 403):
            self._log_failed_attempt(request, body_bytes, response.status_code)

        return response

    def _log_failed_attempt(self, request: Request, raw_body: bytes, status_code: int) -> None:
        """
        Estrutura e emite o log de falha de autenticação com contexto multilocatário.
        """
        sanitized_body = {}
        if raw_body:
            try:
                parsed_json = json.loads(raw_body.decode("utf-8"))
                sanitized_body = sanitize_payload(parsed_json)
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Se não for JSON válido ou falhar na decodificação, loga metadados genéricos
                sanitized_body = {"raw_payload_info": "[NON_JSON_OR_MALFORMED_DATA]"}

        # Identificação de Tenant (Header, Subdomínio ou Payload)
        tenant_identifier = (
            request.headers.get("x-tenant-id")
            or request.headers.get("x-company-slug")
            or (sanitized_body.get("company_slug") if isinstance(sanitized_body, dict) else None)
            or (sanitized_body.get("tenant_id") if isinstance(sanitized_body, dict) else None)
            or "unspecified"
        )

        audit_entry = {
            "event": "AUTH_FAILED",
            "status_code": status_code,
            "tenant_id": sanitize_string(str(tenant_identifier)),
            "client_ip": get_client_ip(request),
            "user_agent": sanitize_string(request.headers.get("user-agent", "unknown")[:255]),
            "path": sanitize_string(request.url.path),
            "method": request.method,
            "submitted_payload": sanitized_body,
        }

        # Emissão como JSON para ingestão segura em SIEM / CloudWatch / Datadog / Elastic
        logger.warning(json.dumps(audit_entry, ensure_ascii=False))