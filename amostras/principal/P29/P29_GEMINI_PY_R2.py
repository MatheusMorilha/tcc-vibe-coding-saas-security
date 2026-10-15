import logging
from typing import Any, Dict
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

# Configuração básica de logging estruturado
logger = logging.getLogger("saas_api")
logging.basicConfig(level=logging.INFO)


# ----------------------------------------------------------------------
# 1. Hierarquia de Exceções de Domínio / Regra de Negócio
# ----------------------------------------------------------------------
class BaseAPIException(Exception):
    """Exceção base para erros de negócio e aplicação."""

    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Dict[str, Any] | None = None,):
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}
        super().__init__(message)


class TenantNotFoundException(BaseAPIException):
    def __init__(self, tenant_id: str):
        super().__init__(
            message=f"Empresa/Locatário com ID '{tenant_id}' não foi encontrado.",
            code="TENANT_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class FeatureAccessDeniedException(BaseAPIException):
    def __init__(self, feature_name: str, plan_name: str):
        super().__init__(
            message=f"A funcionalidade '{feature_name}' não está disponível no plano '{plan_name}'.",
            code="FEATURE_NOT_IN_PLAN",
            status_code=status.HTTP_403_FORBIDDEN,
            details={"feature": feature_name, "current_plan": plan_name},
        )


class SubscriptionExpiredException(BaseAPIException):
    def __init__(self):
        super().__init__(
            message="A assinatura da empresa está expirada ou inativa.",
            code="SUBSCRIPTION_EXPIRED",
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
        )


# ----------------------------------------------------------------------
# 2. Função Auxiliar de Padronização de Respostas
# ----------------------------------------------------------------------
def format_error_response(
    code: str,
    message: str,
    details: Dict[str, Any] | None = None,
    tenant_id: str | None = None,) -> Dict[str, Any]:
    """Cria uma estrutura padronizada para todas as respostas de erro da API."""
    response = {
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
        }
    }
    if tenant_id:
        response["meta"] = {"tenant_id": tenant_id}
    return response


# ----------------------------------------------------------------------
# 3. Mapeamento e Registro dos Handlers Globais
# ----------------------------------------------------------------------
def register_exception_handlers(app: FastAPI) -> None:

    @app.exception_handler(BaseAPIException)
    async def domain_exception_handler(request: Request, exc: BaseAPIException):
        """Intercepta exceções customizadas de domínio do SaaS."""
        tenant_id = getattr(request.state, "tenant_id", None)

        logger.warning(
            f"Erro de Negócio [{exc.code}] | Tenant: {tenant_id} | Path: {request.url.path} | Msg: {exc.message}"
        )

        return JSONResponse(
            status_code=exc.status_code,
            content=format_error_response(
                code=exc.code,
                message=exc.message,
                details=exc.details,
                tenant_id=tenant_id,
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError):
        """Intercepta erros de validação dos dados de entrada (FastAPI/Pydantic)."""
        tenant_id = getattr(request.state, "tenant_id", None)

        # Formata erros do Pydantic para um formato limpo
        errors = [
            {"field": ".".join(map(str, err["loc"])), "issue": err["msg"]}
            for err in exc.errors()
        ]

        logger.info(f"Falha de Validação | Tenant: {tenant_id} | Path: {request.url.path}")

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=format_error_response(
                code="VALIDATION_ERROR",
                message="Parâmetros ou corpo da requisição inválidos.",
                details={"errors": errors},
                tenant_id=tenant_id,
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        """Intercepta exceções HTTP padrão do framework (ex: 404 Not Found em rotas)."""
        tenant_id = getattr(request.state, "tenant_id", None)

        return JSONResponse(
            status_code=exc.status_code,
            content=format_error_response(
                code=f"HTTP_{exc.status_code}",
                message=str(exc.detail),
                tenant_id=tenant_id,
            ),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        """Catch-all: Intercepta qualquer exceção inesperada (Erros 500 sem tratamento específico)."""
        tenant_id = getattr(request.state, "tenant_id", None)

        # Registra o erro completo com traceback para auditoria e depuração de TI
        logger.error(
            f"Erro Não Tratado (500) | Tenant: {tenant_id} | Path: {request.url.path}",
            exc_info=exc,
        )

        # Retorna uma mensagem genérica e segura para não expor detalhes técnicos do banco ou servidor
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=format_error_response(
                code="INTERNAL_SERVER_ERROR",
                message="Ocorreu um erro interno inesperado no servidor. Tente novamente mais tarde.",
                tenant_id=tenant_id,
            ),
        )

# Inicialização do FastAPI
app = FastAPI(title="SaaS Multi-Tenant Management API")

# Registrar os handlers globais
register_exception_handlers(app)


# Middleware simulado para isolar o locatário/tenant em cada requisição
@app.middleware("http")
async def tenant_context_middleware(request: Request, call_next):
    # Exemplo extraindo o tenant do cabeçalho HTTP
    request.state.tenant_id = request.headers.get("X-Tenant-ID", "desconhecido")
    response = await call_next(request)
    return response


# Rotas da API demonstrando o lançamento das exceções
@app.get("/api/v1/relatorios/financeiro")
async def obter_relatorio_financeiro(request: Request):
    # Exemplo: Verificação de plano
    plano_atual = "Básico"
    feature_requerida = "Relatórios Avançados"

    if plano_atual == "Básico":
        raise FeatureAccessDeniedException(
            feature_name=feature_requerida, plan_name=plano_atual
        )

    return {"status": "sucesso", "data": {}}


@app.get("/api/v1/locatarios/{tenant_id}")
async def obter_locatario(tenant_id: str):
    # Exemplo: Locatário não encontrado no DB
    if tenant_id != "empresa-123":
        raise TenantNotFoundException(tenant_id=tenant_id)

    return {"id": tenant_id, "status": "active"}


@app.get("/api/v1/erro-inesperado")
async def simular_erro_fatal():
    # Exemplo: Erro não capturado (divisão por zero ou falha de conexão)
    return 10 / 0