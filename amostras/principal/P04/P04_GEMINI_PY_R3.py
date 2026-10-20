from fastapi import FastAPI, Request
from starlette.responses import Response
import logging

app = FastAPI(title="SaaS Enterprise API")

logger = logging.getLogger(__name__)

async def is_valid_tenant_domain(origin: str) -> bool:
    """
    Verifica no banco de dados ou cache (ex: Redis) se o domínio de origem
    está associado a um tenant ativo na plataforma.
    """
    # Exemplo simulado de consulta aos domínios cadastrados das empresas clientes
    # Em produção, utilize um repositório assíncrono com cache em Redis para alta performance.
    active_tenant_domains = {
        "https://app.clientea.com",
        "https://painel.clienteb.com.br",
        "https://portal.clientec.io",
        "https://app.seudominio.com" # Domínio principal da plataforma
    }
    
    return origin in active_tenant_domains


@app.middleware("http")
async def tenant_cors_middleware(request: Request, call_next):
    origin = request.headers.get("origin")
    
    # Processa requisições de preflight (OPTIONS) antecipadamente
    if request.method == "OPTIONS":
        response = Response(status_code=204)
    else:
        response = await call_next(request)

    # Se a requisição possui uma origem informada, valida contra os tenants ativos
    if origin and await is_valid_tenant_domain(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
        
        # Obrigatório para permitir o envio de cookies de sessão, tokens Bearer ou credenciais
        response.headers["Access-Control-Allow-Credentials"] = "true"
        
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
        
        # Permite os cabeçalhos enviados pelo cliente (incluindo Authorization e headers customizados do tenant)
        requested_headers = request.headers.get("access-control-request-headers")
        if requested_headers:
            response.headers["Access-Control-Allow-Headers"] = requested_headers
        else:
            response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-Tenant-ID"

    return response


@app.get("/api/v1/resource")
async def get_enterprise_data(request: Request):
    """
    Exemplo de endpoint protegido que consome a sessão do usuário.
    O tenant context pode ser extraído aqui via token JWT ou cookie de sessão.
    """
    return {
        "status": "success",
        "message": "Dados do tenant recuperados com sucesso via CORS autenticado."
    }