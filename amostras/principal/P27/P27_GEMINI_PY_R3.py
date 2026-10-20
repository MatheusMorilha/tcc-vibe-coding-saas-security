import time
import json
import logging
import uuid
from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Configuração do logger estruturado
logger = logging.getLogger("saas.audit")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

class TenantRequestAuditMiddleware(BaseHTTPMiddleware):
    """
    Middleware para auditoria e log de requisições em arquitetura SaaS multilocatária.
    Captura metadados de tenant, usuário, payload e tempo de resposta.
    """
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())
        start_time = time.time()
        
        # Identificação do Tenant e Usuário (extraídos de headers de autenticação ou gateway)
        tenant_id = request.headers.get("X-Tenant-ID", "unknown")
        user_id = request.headers.get("X-User-ID", "unknown")
        
        # Captura segura do corpo da requisição sem consumir o stream definitivo
        body_bytes = await request.body()
        
        # Restaura o receive para que os endpoints da aplicação consigam ler o body normalmente
        async def receive():
            return {"type": "http.request", "body": body_bytes}
        request._receive = receive
        
        # Conversão do corpo para JSON se aplicável, ou tratamento como string
        body_content = None
        if body_bytes:
            try:
                body_content = json.loads(body_bytes.decode("utf-8"))
            except json.JSONDecodeError:
                body_content = body_bytes.decode("utf-8", errors="ignore")

        # Sanitização de headers sensíveis (ex: tokens de autorização, senhas)
        headers = dict(request.headers)
        sensitive_headers = ["authorization", "cookie", "x-api-key"]
        for header in sensitive_headers:
            if header in headers:
                headers[header] = "[REDACTED]"

        # Montagem do payload de auditoria da requisição
        audit_data = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "method": request.method,
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "headers": headers,
            "body": body_content
        }

        # Execução da requisição
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as exc:
            # Em caso de erro não tratado, registra o status de falha interna
            duration_ms = round((time.time() - start_time) * 1000, 2)
            audit_data.update({
                "status_code": 500,
                "duration_ms": duration_ms,
                "error": str(exc)
            })
            logger.info(json.dumps(audit_data, ensure_ascii=False))
            raise exc

        # Cálculo do tempo de resposta
        duration_ms = round((time.time() - start_time) * 1000, 2)
        
        audit_data.update({
            "status_code": status_code,
            "duration_ms": duration_ms
        })

        # Emite log estruturado (ideal para indexação em ELK, Datadog ou CloudWatch)
        logger.info(json.dumps(audit_data, ensure_ascii=False))
        
        # Injeta o Request ID no cabeçalho da resposta para rastreabilidade do cliente
        response.headers["X-Request-ID"] = request_id
        return response

# Exemplo de inicialização da aplicação FastAPI
app = FastAPI(title="SaaS Business Management API")
app.add_middleware(TenantRequestAuditMiddleware)

@app.post("/api/v1/companies/{company_id}/resources")
async def create_resource(company_id: str, request: Request):
    # Lógica de negócio da aplicação (compartilhada no mesmo banco de dados com filtro por tenant)
    body = await request.json()
    return {"status": "success", "company_id": company_id, "data_received": body}