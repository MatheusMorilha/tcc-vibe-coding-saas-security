import json
import logging
from typing import Callable, Any
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Configuração do Logger Estruturado
logger = logging.getLogger("auth_security_audit")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# Lista de chaves restritas pela OWASP (evita vazamento de segredos em logs)
SENSITIVE_KEYS = {
    "password", "senha", "token", "secret", "authorization",
    "access_token", "refresh_token", "credit_card", "cvv"
}

def sanitize_payload(data: Any) -> Any:
    """
    Remove ou mascara recursivamente dados confidenciais do payload
    para prevenir exposição de segredos nos logs (OWASP A02/A09).
    """
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            if key.lower() in SENSITIVE_KEYS:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = sanitize_payload(value)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_payload(item) for item in data]
    return data

def get_client_ip(request: Request) -> str:
    """Extrai o IP real considerando headers de proxy reverso."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class FailedAuthAuditMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, auth_routes: set[str] = None):
        super().__init__(app)
        # Rotas críticas de autenticação a serem monitoradas
        self.auth_routes = auth_routes or {
            "/api/v1/auth/login",
            "/api/v1/auth/token",
            "/api/v1/tenant/login"
        }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Se não for uma rota monitorada ou não for POST, segue o fluxo normal
        if request.url.path not in self.auth_routes or request.method != "POST":
            return await call_next(request)

        # Consome o corpo da requisição para leitura segura
        body_bytes = await request.body()

        # O Starlette consome o stream de dados; recriamos o reader para a aplicação
        async def receive():
            return {"type": "http.request", "body": body_bytes, "more_body": False}

        request = Request(request.scope, receive=receive)

        # Executa a rota na aplicação
        response: Response = await call_next(request)

        # Códigos 401 (Unauthorized) e 403 (Forbidden) indicam falha na autenticação/autorização
        if response.status_code in (401, 403):
            await self._log_failed_attempt(request, body_bytes, response.status_code)

        return response

    async def _log_failed_attempt(self, request: Request, body_bytes: bytes, status_code: int):
        try:
            # Parse seguro do corpo JSON
            raw_payload = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            raw_payload = {"_raw_payload_error": "corpo_invalido_ou_nao_json"}

        # Mascara segredos antes de persistir no log
        safe_payload = sanitize_payload(raw_payload)

        # Identificação de contexto multilocatário (se fornecido na requisição)
        tenant_hint = (
            safe_payload.get("tenant_id")
            or safe_payload.get("company_slug")
            or request.headers.get("x-tenant-id")
            or "unspecified"
        )

        audit_entry = {
            "event": "FAILED_AUTHENTICATION_ATTEMPT",
            "status_code": status_code,
            "path": request.url.path,
            "method": request.method,
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", "unknown"),
            "tenant_identifier": tenant_hint,
            # Sanitizado: o suporte vê username/tenant, mas senhas vêm como [REDACTED]
            "request_payload": safe_payload
        }

        # JSON em linha única previne Log Injection (CWE-117) via quebras de linha (\n ou \r)
        logger.warning(json.dumps(audit_entry, ensure_ascii=False))