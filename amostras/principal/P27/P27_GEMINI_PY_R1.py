import time
import json
import logging
import uuid
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

# Configuração do logger estruturado para a equipe de suporte
logger = logging.getLogger("saas.api.audit")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

class TenantRequestLoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        # 1. Identificador único de rastreio (Correlation ID) para correlacionar logs de uma mesma chamada
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        
        # 2. Captura de metadados temporais
        start_time = time.time()
        
        # 3. Extração de contexto do Tenant e Usuário (assumindo que são injetados via headers ou pelo Auth Middleware prévio)
        tenant_id = request.headers.get("X-Tenant-ID", "unknown_tenant")
        user_id = request.headers.get("X-User-ID", "anonymous")

        # 4. Leitura segura do corpo da requisição (se houver)
        req_body = b""
        if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
            try:
                req_body = await request.body()
                # Reatribui o corpo para que os endpoints possam consumi-lo normalmente após a leitura do middleware
                async def receive():
                    return {"type": "http.request", "body": req_body}
                request._receive = receive
            except Exception:
                req_body = b"<failed_to_read_body>"

        # Tenta decodificar o corpo para JSON legível no log, se aplicável
        parsed_body = None
        if req_body and req_body != b"<failed_to_read_body>":
            try:
                parsed_body = json.loads(req_body.decode("utf-8"))
                # Opcional: mascarar campos sensíveis como senhas ou tokens
                if isinstance(parsed_body, dict):
                    for sensitive_field in ["password", "senha", "credit_card", "token"]:
                        if sensitive_field in parsed_body:
                            parsed_body[sensitive_field] = "********"
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed_body = req_body.decode("utf-8", errors="ignore")

        # 5. Execução da requisição
        response = None
        status_code = 500
        error_message = None

        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as exc:
            status_code = 500
            error_message = str(exc)
            raise exc
        finally:
            # 6. Cálculo do tempo de processamento
            duration_ms = round((time.time() - start_time) * 1000, 2)

            # 7. Montagem do payload de log estruturado para o suporte
            log_data = {
                "request_id": request_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "method": request.method,
                "url": str(request.url),
                "query_params": dict(request.query_params),
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "request_body": parsed_body,
                "response_status": status_code,
                "duration_ms": duration_ms,
                "error": error_message
            }

            # Registro do log em formato JSON para fácil indexação
            logger.info(json.dumps(log_data, ensure_ascii=False))
            
            # Adiciona o Request ID no cabeçalho da resposta para facilitar o report do cliente/suporte
            if response:
                response.headers["X-Request-ID"] = request_id

        return response