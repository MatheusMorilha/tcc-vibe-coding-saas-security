"""
error_handlers.py - Tratamento global de erros da API SaaS multilocatária.

Princípios:
  * O cliente NUNCA recebe stack trace, mensagem de exceção interna, SQL,
    caminhos de arquivo ou valores enviados na requisição (em 5xx).
  * Todo erro devolve o mesmo envelope JSON e um request_id para suporte.
  * O log interno carrega contexto de tenant/usuário para investigação,
    mas sem corpo da requisição, query string ou headers (podem ter
    tokens, senhas e dados pessoais).
  * Erros de domínio expõem apenas mensagens que o desenvolvedor marcou
    explicitamente como seguras.
"""
from __future__ import annotations

import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("api.errors")

REQUEST_ID_HEADER = "X-Request-ID"

GENERIC_MESSAGES = {
    400: "Requisição inválida.",
    401: "Autenticação necessária.",
    403: "Você não tem permissão para realizar esta ação.",
    404: "Recurso não encontrado.",
    405: "Método não permitido.",
    409: "Conflito ao processar a requisição.",
    422: "Dados inválidos.",
    429: "Muitas requisições. Tente novamente em instantes.",
    500: "Erro interno do servidor.",
}


# --------------------------------------------------------------------------
# Exceções de domínio: o message é SEGURO para o cliente.
# --------------------------------------------------------------------------
class AppError(Exception):
    status_code = 400
    code = "app_error"
    message = "Não foi possível processar a requisição."

    def __init__(self, message: str | None = None, *, headers: dict | None = None):
        self.message = message or self.message
        self.headers = headers
        super().__init__(self.message)


class NotFoundError(AppError):
    # Use também quando o recurso existe em OUTRO tenant: devolver 404 (e não
    # 403) evita que um tenant descubra a existência de dados de outro.
    status_code, code, message = 404, "not_found", "Recurso não encontrado."


class PermissionDeniedError(AppError):
    status_code, code, message = 403, "forbidden", "Acesso negado."


class PlanLimitExceededError(AppError):
    status_code, code = 402, "plan_limit_exceeded"
    message = "O plano atual não permite esta operação."


class SubscriptionInactiveError(AppError):
    status_code, code = 402, "subscription_inactive"
    message = "A assinatura da empresa não está ativa."


class ConflictError(AppError):
    status_code, code, message = 409, "conflict", "Conflito ao processar a requisição."


# --------------------------------------------------------------------------
# Utilitários
# --------------------------------------------------------------------------
def get_request_id(request: Request) -> str:
    rid = getattr(request.state, "request_id", None)
    if not rid:
        incoming = request.headers.get(REQUEST_ID_HEADER, "")
        # Aceita ID do cliente só se for um formato inofensivo (evita log injection).
        rid = incoming if _is_safe_id(incoming) else uuid.uuid4().hex
        request.state.request_id = rid
    return rid


def _is_safe_id(value: str) -> bool:
    return 0 < len(value) <= 64 and all(c.isalnum() or c in "-_" for c in value)


def _log_context(request: Request, request_id: str) -> dict:
    # tenant_id e user_id devem ser preenchidos pela camada de autenticação
    # em request.state. Se a falha ocorrer antes dela, ficam None.
    return {
        "request_id": request_id,
        "tenant_id": getattr(request.state, "tenant_id", None),
        "user_id": getattr(request.state, "user_id", None),
        "method": request.method,
        "path": request.url.path,  # sem query string: pode conter tokens
    }


def _build_response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    *,
    details: list | None = None,
    headers: dict | None = None,
) -> JSONResponse:
    request_id = get_request_id(request)
    body: dict = {"error": {"code": code, "message": message, "request_id": request_id}}
    if details:
        body["error"]["details"] = details
    out_headers = dict(headers or {})
    out_headers[REQUEST_ID_HEADER] = request_id
    return JSONResponse(status_code=status_code, content=body, headers=out_headers)


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------
async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    ctx = _log_context(request, get_request_id(request))
    logger.warning("Erro de domínio: %s", exc.code, extra=ctx)
    return _build_response(
        request, exc.status_code, exc.code, exc.message, headers=exc.headers
    )


async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    ctx = _log_context(request, get_request_id(request))
    status = exc.status_code

    if status >= 500:
        logger.error("HTTPException %s: %r", status, exc.detail, extra=ctx)
        message = GENERIC_MESSAGES.get(status, GENERIC_MESSAGES[500])
    else:
        logger.info("HTTPException %s", status, extra=ctx)
        # detail em 4xx costuma ser texto escrito pelo dev; se não for str,
        # cai na mensagem genérica para não serializar objetos arbitrários.
        message = exc.detail if isinstance(exc.detail, str) else GENERIC_MESSAGES.get(
            status, "Requisição não pôde ser atendida."
        )

    return _build_response(
        request,
        status,
        f"http_{status}",
        message,
        headers=getattr(exc, "headers", None),  # preserva WWW-Authenticate, Retry-After
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    ctx = _log_context(request, get_request_id(request))
    logger.info("Falha de validação (%d erro(s))", len(exc.errors()), extra=ctx)

    # Apenas campo e mensagem. Nunca devolver "input" nem "ctx": ecoariam
    # valores enviados pelo cliente (senhas, tokens, documentos).
    details = [
        {
            "field": ".".join(str(p) for p in err.get("loc", ()) if p != "body"),
            "message": err.get("msg", "Valor inválido."),
        }
        for err in exc.errors()
    ]
    return _build_response(
        request, 422, "validation_error", GENERIC_MESSAGES[422], details=details
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Último recurso: qualquer exceção não prevista vira um 500 opaco."""
    ctx = _log_context(request, get_request_id(request))
    # Traceback completo apenas no log interno (ex.: enviado ao Sentry/ELK).
    logger.error(
        "Exceção não tratada: %s", type(exc).__name__, exc_info=exc, extra=ctx
    )
    return _build_response(request, 500, "internal_error", GENERIC_MESSAGES[500])


# --------------------------------------------------------------------------
# Registro
# --------------------------------------------------------------------------
def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)


# Exemplo de uso:
#
#   app = FastAPI()
#   register_error_handlers(app)
#
#   @app.get("/invoices/{invoice_id}")
#   async def get_invoice(invoice_id: int, ctx=Depends(current_tenant_ctx)):
#       invoice = await repo.get(invoice_id, tenant_id=ctx.tenant_id)
#       if invoice is None:
#           raise NotFoundError()          # 404 também para outro tenant
#       return invoice