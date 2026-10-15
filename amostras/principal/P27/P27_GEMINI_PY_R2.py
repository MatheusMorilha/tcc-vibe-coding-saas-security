import json
import logging
import time
import uuid
from typing import Callable, Any, Dict, List
from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import Message

# Configuração de Logger estruturado em JSON para facilitar parser no Datadog, ELK, etc.
logger = logging.getLogger("audit_logger")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(handler)

# Chaves sensíveis que NUNCA devem ser salvas em log
SENSITIVE_KEYS: List[str] = [
    "password", "senha", "token", "access_token",
    "refresh_token", "secret", "credit_card", "cvv"
]


def sanitize_payload(payload: Any) -> Any:
    """
    Sanitiza recursivamente dicionários e listas para omitir dados sensíveis.
    """
    if isinstance(payload, dict):
        sanitized = {}
        for key, value in payload.items():
            if any(sensitive in key.lower() for sensitive in SENSITIVE_KEYS):
                sanitized[key] = "[FILTERED]"
            else:
                sanitized[key] = sanitize_payload(value)
        return sanitized
    elif isinstance(payload, list):
        return [sanitize_payload(item) for item in payload]
    return payload


class SaaSRequestAuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()

        # 1. Rastreabilidade com Request ID
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

        # 2. Identificação do Locatário (Tenant) e Usuário
        # Em uma app real, estes valores vêm de headers, subdomínios ou JWT decodificado
        tenant_id = request.headers.get("X-Tenant-ID", "anonymous")
        user_id = request.headers.get("X-User-ID", "anonymous")

        # 3. Leitura e Sanitização do Corpo da Requisição (Body)
        # O streaming do body precisa ser recriado após a leitura para não travar os endpoints
        req_body_bytes = await request.body()

        async def receive() -> Message:
            return {"type": "http.request", "body": req_body_bytes}

        request = Request(request.scope, receive=receive)

        parsed_body = None
        if req_body_bytes:
            try:
                raw_json = json.loads(req_body_bytes.decode("utf-8"))
                parsed_body = sanitize_payload(raw_json)
            except Exception:
                parsed_body = "[Non-JSON or Unparseable Binary Body]"

        # 4. Execução da Requisição
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as exc:
            status_code = 500
            # Registra a falha antes de propagar a exceção
            self._log_request(
                request_id=request_id,
                tenant_id=tenant_id,
                user_id=user_id,
                method=request.method,
                path=request.url.path,
                query_params=dict(request.query_params),
                body=parsed_body,
                status_code=status_code,
                duration_ms=round((time.time() - start_time) * 1000, 2),
                error=str(exc)
            )
            raise exc

        # 5. Registro do Log Estruturado
        duration_ms = round((time.time() - start_time) * 1000, 2)
        response.headers["X-Request-ID"] = request_id

        self._log_request(
            request_id=request_id,
            tenant_id=tenant_id,
            user_id=user_id,
            method=request.method,
            path=request.url.path,
            query_params=dict(request.query_params),
            body=parsed_body,
            status_code=status_code,
            duration_ms=duration_ms
        )

        return response

    def _log_request(
        self,
        request_id: str,
        tenant_id: str,
        user_id: str,
        method: str,
        path: str,
        query_params: Dict[str, Any],
        body: Any,
        status_code: int,
        duration_ms: float,
        error: str = None) -> None:
        log_entry = {
            "event": "http_request_audit",
            "request_id": request_id,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "http": {
                "method": method,
                "path": path,
                "query_params": query_params,
                "status_code": status_code,
                "duration_ms": duration_ms
            },
            "payload": body
        }

        if error:
            log_entry["error"] = error

        logger.info(json.dumps(log_entry))