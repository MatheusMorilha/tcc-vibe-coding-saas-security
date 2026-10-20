import logging
import traceback
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

# Configuração básica de logging para auditoria e rastreio de erros
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("saas_api")

app = FastAPI(title="SaaS Enterprise Management API")

# --- Exceções de Domínio / Negócio ---

class AppException(Exception):
    """Classe base para exceções de negócio da aplicação."""
    def __init__(self, message: str, status_code: int, error_code: str):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        super().__init__(self.message)

class TenantNotFoundException(AppException):
    def __init__(self):
        super().__init__(
            message="A organização informada não foi encontrada ou está inativa.",
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="TENANT_NOT_FOUND"
        )

class InactiveSubscriptionException(AppException):
    def __init__(self):
        super().__init__(
            message="O plano de assinatura desta organização está expirado ou inativo.",
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="INACTIVE_SUBSCRIPTION"
        )


# --- Tratadores Globais de Erros ---

@app.exception_handler(AppException)
async def app_exception_handler(request: Request, exc: AppException):
    """
    Intercepta exceções controladas de regra de negócio do SaaS
    e retorna uma resposta padronizada para o cliente.
    """
    logger.warning(
        f"Erro de negócio [{exc.error_code}] na rota {request.url.path}: {exc.message}"
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": {
                "code": exc.error_code,
                "message": exc.message
            }
        }
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """
    Tratador global de falhas críticas e erros não previstos (500).
    Garante que nenhum stack trace interno seja exposto ao cliente final.
    """
    # Log detalhado do erro real com traceback completo apenas no servidor
    tb_str = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    logger.error(f"Erro crítico não tratado na rota {request.url.path}:\n{tb_str}")

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "Ocorreu um erro interno inesperado. Nossa equipe técnica já foi notificada."
            }
        }
    )


# --- Exemplo de Rota para Teste ---

@app.get("/api/v1/tenant-data")
async def get_tenant_data(tenant_id: str = None):
    if not tenant_id:
        raise TenantNotFoundException()
    
    # Exemplo simulando verificação de plano de assinatura ativo
    if tenant_id == "expired-tenant":
        raise InactiveSubscriptionException()
        
    # Exemplo de erro não tratado (ex: divisão por zero ou falha de banco)
    if tenant_id == "crash":
        raise ZeroDivisionError("Erro simulado no banco de dados")

    return {"success": True, "data": f"Dados protegidos do tenant {tenant_id}"}