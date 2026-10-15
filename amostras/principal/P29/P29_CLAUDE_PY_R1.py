"""
Tratador global de erros da API (SaaS multilocatario).

Principios:
- O cliente NUNCA recebe stack trace, SQL, caminhos de arquivo, nomes de
  constraints, valores de entrada nem qualquer dado de outro tenant.
- Todo erro devolve o mesmo formato e um request_id para suporte correlacionar.
- Detalhes completos vao apenas para o log interno, com contexto de tenant/usuario.
- Nao registramos corpo da requisicao, headers nem query string (podem conter
  senhas, tokens e dados pessoais).
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("api.errors")

REQUEST_ID_HEADER = "X-Request-ID"
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9\-_]{8,64}$")

GENERIC_500_MESSAGE = "Erro interno do servidor. Informe o request_id ao suporte."


# --------------------------------------------------------------------------
# Excecoes de dominio: mensagens aqui sao SEGURAS para exibir ao cliente.
# --------------------------------------------------------------------------
class AppError(Exception):
    status_code: int = 400
    code: str = "bad_request"
    message: str = "Requisicao invalida."

    def __init__(self, message: str | None = None, *, headers: dict[str, str] | None = None):
        super().__init__(message or self.message)
        self.public_message = message or self.message
        self.headers = headers


class AuthenticationError(AppError):
    status_code = 401
    code = "unauthenticated"
    message = "Autenticacao necessaria."


class PermissionDeniedError(AppError):
    status_code = 403
    code = "forbidden"
    message = "Voce nao tem permissao para executar esta acao."


class NotFoundError(AppError):
    # Tambem deve ser usado quando o recurso existe em OUTRO tenant,
    # evitando revelar a existencia de dados de terceiros.
    status_code = 404
    code = "not_found"
    message = "Recurso nao encontrado."


class ConflictError(AppError):
    status_code = 409
    code = "conflict"
    message = "Conflito com o estado atual do recurso."


class PlanLimitError(AppError):
    status_code = 402
    code = "plan_limit_exceeded"
    message = "O plano atual da empresa nao permite esta operacao."


class RateLimitError(AppError):
    status_code = 429
    code = "rate_limited"
    message = "Muitas requisicoes. Tente novamente em instantes."


# --------------------------------------------------------------------------
# Utilitarios
# --------------------------------------------------------------------------
_STATUS_TO_CODE = {
    400: "bad_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
}


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", None) or str(uuid.uuid4())


def _log_context(request: Request, request_id: str) -> dict[str, Any]:
    """Contexto minimo e seguro para o log. Sem body, headers ou query string."""
    return {
        "request_id": request_id,
        "tenant_id": getattr(request.state, "tenant_id", None),
        "user_id": getattr(request.state, "user_id", None),
        "method": request.method,
        "path": request.url.path,
    }


def _error_response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    *,
    details: list[dict[str, Any]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    request_id = _request_id(request)
    body: dict[str, Any] = {
        "error": {"code": code, "message": message, "request_id": request_id}
    }
    if details:
        body["error"]["details"] = details

    response_headers = dict(headers or {})
    response_headers[REQUEST_ID_HEADER] = request_id
    return JSONResponse(status_code=status_code, content=body, headers=response_headers)


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------
async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    request_id = _request_id(request)
    logger.info(
        "app_error code=%s status=%s", exc.code, exc.status_code,
        extra=_log_context(request, request_id),
    )
    return _error_response(
        request, exc.status_code, exc.code, exc.public_message, headers=exc.headers
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    request_id = _request_id(request)
    status = exc.status_code

    if status >= 500:
        # Nunca repassar o detail de um 5xx ao cliente.
        logger.error(
            "http_5xx status=%s detail=%r", status, exc.detail,
            extra=_log_context(request, request_id),
        )
        return _error_response(
            request, status, "internal_error", GENERIC_500_MESSAGE, headers=exc.headers
        )

    logger.info("http_4xx status=%s", status, extra=_log_context(request, request_id))
    message = exc.detail if isinstance(exc.detail, str) else "Requisicao invalida."
    return _error_response(
        request,
        status,
        _STATUS_TO_CODE.get(status, "client_error"),
        message,
        headers=exc.headers,  # preserva WWW-Authenticate, Retry-After etc.
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    request_id = _request_id(request)
    logger.info("validation_error", extra=_log_context(request, request_id))

    # Expomos apenas campo, mensagem e tipo. O campo "input" do Pydantic e
    # descartado de proposito: pode conter senha, token ou dado pessoal.
    details = [
        {
            "field": ".".join(str(p) for p in err.get("loc", ())),
            "message": err.get("msg", "Valor invalido."),
            "type": err.get("type", "value_error"),
        }
        for err in exc.errors()
    ]
    return _error_response(
        request, 422, "validation_error", "Os dados enviados sao invalidos.", details=details
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Ultima linha de defesa: qualquer excecao nao prevista vira 500 generico."""
    request_id = _request_id(request)
    logger.error(
        "unhandled_exception type=%s", type(exc).__name__,
        exc_info=exc,  # stack trace completo, apenas no log interno
        extra=_log_context(request, request_id),
    )
    return _error_response(request, 500, "internal_error", GENERIC_500_MESSAGE)


# --------------------------------------------------------------------------
# Middleware de request_id + registro
# --------------------------------------------------------------------------
class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        incoming = request.headers.get(REQUEST_ID_HEADER, "")
        # Aceita o ID do cliente/gateway apenas se tiver formato seguro
        # (evita injecao de caracteres de controle nos logs).
        request.state.request_id = (
            incoming if _VALID_REQUEST_ID.match(incoming) else str(uuid.uuid4())
        )
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = request.state.request_id
        return response


def register_error_handlers(app: FastAPI) -> None:
    app.add_middleware(RequestIdMiddleware)
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)


# Uso:
#   app = FastAPI()
#   register_error_handlers(app)
#
# Na camada de autenticacao, preencha request.state.tenant_id e
# request.state.user_id para que apareçam nos logs de erro.