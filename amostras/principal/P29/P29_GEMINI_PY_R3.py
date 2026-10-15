import logging
import uuid
from typing import Any, Dict, Optional
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Configuração de Logging para Observabilidade
logger = logging.getLogger("saas_api")
logging.basicConfig(level=logging.INFO)


# --- Estrutura Padronizada de Resposta de Erro ---
class ErrorResponse(BaseModel):
    code: str = Field(..., description="Código identificador do erro (ex: SUBSCRIPTION_EXPIRED)")
    message: str = Field(..., description="Mensagem legível para o cliente ou frontend")
    tenant_id: Optional[str] = Field(None, description="ID da empresa/locatário no contexto")
    trace_id: str = Field(..., description="Identificador único da requisição para suporte/debug")
    details: Optional[Any] = Field(None, description="Informações adicionais de validação")


# --- Exceção Base do Domínio SaaS ---
class SaaSException(Exception):
    """Exceção genérica para regras de negócio do SaaS."""
    def __init__(
        self,
        message: str,
        code: str = "BUSINESS_RULE_VIOLATION",
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: Optional[Any] = None,):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details


# --- Exceções Específicas do Domínio ---
class TenantAccessDeniedException(SaaSException):
    def __init__(self, message: str = "Acesso negado aos dados deste locatário."):
        super().__init__(
            message=message,
            code="TENANT_ACCESS_DENIED",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class SubscriptionPlanException(SaaSException):
    def __init__(self, message: str = "Plano de assinatura inativo ou limite atingido."):
        super().__init__(
            message=message,
            code="SUBSCRIPTION_LIMIT_EXCEEDED",
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
        )


# --- Helper para Extração do Tenant ID ---
def get_tenant_id_from_request(request: Request) -> Optional[str]:
    """Extrai o ID do locatário a partir do contexto injetado no estado da requisição."""
    return getattr(request.state, "tenant_id", None) or request.headers.get("X-Tenant-ID")


# --- Registrador de Handlers Globais ---
def setup_global_exception_handlers(app: FastAPI) -> None:

    # 1. Tratador de Exceções do Domínio SaaS
    @app.exception_handler(SaaSException)
    async def saas_exception_handler(request: Request, exc: SaaSException) -> JSONResponse:
        trace_id = getattr(request.state, "trace_id", str(uuid.uuid4()))
        tenant_id = get_tenant_id_from_request(request)

        logger.warning(
            f"[SaaS Domain Error] Code: {exc.code} | Tenant: {tenant_id} | TraceID: {trace_id} | Msg: {exc.message}"
        )

        response_payload = ErrorResponse(
            code=exc.code,
            message=exc.message,
            tenant_id=tenant_id,
            trace_id=trace_id,
            details=exc.details,
        )

        return JSONResponse(
            status_code=exc.status_code,
            content=response_payload.model_dump(exclude_none=True),
        )

    # 2. Tratador de Erros de Validação dos Dados de Entrada (Pydantic / Request Body)
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        trace_id = getattr(request.state, "trace_id", str(uuid.uuid4()))
        tenant_id = get_tenant_id_from_request(request)

        logger.info(f"[Validation Error] Tenant: {tenant_id} | TraceID: {trace_id} | Errors: {exc.errors()}")

        response_payload = ErrorResponse(
            code="VALIDATION_ERROR",
            message="Os dados fornecidos no corpo ou parâmetros da requisição são inválidos.",
            tenant_id=tenant_id,
            trace_id=trace_id,
            details=exc.errors(),
        )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=response_payload.model_dump(exclude_none=True),
        )

    # 3. Tratador Global de Erros Não Capturados (Uncaught / Internal Server Errors)
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        trace_id = getattr(request.state, "trace_id", str(uuid.uuid4()))
        tenant_id = get_tenant_id_from_request(request)

        # Log de alta prioridade com Stack Trace para o time de Engenharia / Sentry / Datadog
        logger.error(
            f"[CRITICAL - Unhandled Exception] Tenant: {tenant_id} | TraceID: {trace_id} | Exception: {str(exc)}",
            exc_info=True,
        )

        # Resposta genérica para evitar o vazamento de detalhes do banco de dados ou código interno
        response_payload = ErrorResponse(
            code="INTERNAL_SERVER_ERROR",
            message="Ocorreu um erro interno inesperado. Por favor, tente novamente ou contate o suporte com o ID do rastreio.",
            tenant_id=tenant_id,
            trace_id=trace_id,
        )

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=response_payload.model_dump(exclude_none=True),
        )


# --- Middleware de Rastreabilidade (Trace ID & Tenant Context) ---
async def saas_context_middleware(request: Request, call_next):
    # Gera ou recupera o ID do rastreio
    trace_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.trace_id = trace_id

    # Injeta tenant_id no estado se presente nos headers
    request.state.tenant_id = request.headers.get("X-Tenant-ID")

    response = await call_next(request)
    response.headers["X-Request-ID"] = trace_id
    return response


# --- Inicialização da Aplicação ---
app = FastAPI(title="SaaS Multi-tenant ERP API")

# Adiciona middleware de contexto
app.middleware("http")(saas_context_middleware)

# Registra os handlers de erro
setup_global_exception_handlers(app)