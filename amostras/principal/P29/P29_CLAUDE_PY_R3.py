"""
error_handling.py

Tratador global de erros da API (FastAPI/Starlette) para plataforma SaaS multilocatária.

Princípios:
  1. O cliente NUNCA recebe stack trace, SQL, nomes de tabelas/constraints,
     caminhos de arquivo ou valores de entrada ecoados.
  2. Todo erro tem um formato único e um identificador (error_id) para correlação
     com os logs internos.
  3. Os logs internos carregam o contexto do tenant/usuário, mas nunca corpo da
     requisição, tokens, cabeçalhos de autorização ou dados de negócio.
  4. Falhas de isolamento entre tenants não revelam a existência do recurso
     (responde-se 404, não 403).
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

try:  # opcional: só mapeia erros de banco se SQLAlchemy estiver presente
    from sqlalchemy.exc import (
        DBAPIError,
        IntegrityError,
        OperationalError,
        TimeoutError as SATimeoutError,
    )
except ImportError:  # pragma: no cover
    IntegrityError = OperationalError = SATimeoutError = DBAPIError = None  # type: ignore

logger = logging.getLogger("api.errors")

REQUEST_ID_HEADER = "X-Request-ID"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9\-_]{8,64}$")


# --------------------------------------------------------------------------- #
# Exceções de domínio: mensagens aqui são SEGURAS para exibição ao cliente.
# --------------------------------------------------------------------------- #
class AppError(Exception):
    status_code: int = 500
    code: str = "internal_error"
    public_message: str = "Erro interno."

    def __init__(self, public_message: str | None = None, *, extra: dict[str, Any] | None = None):
        super().__init__(public_message or self.public_message)
        if public_message:
            self.public_message = public_message
        # `extra` só deve conter dados seguros e já autorizados para o cliente.
        self.extra = extra or {}


class NotFoundError(AppError):
    status_code, code, public_message = 404, "not_found", "Recurso não encontrado."


class CrossTenantAccessError(NotFoundError):
    """Acesso a recurso de outro tenant. Para o cliente é indistinguível de 404
    (evita enumeração de recursos); internamente é logado como evento de segurança."""


class UnauthorizedError(AppError):
    status_code, code, public_message = 401, "unauthorized", "Autenticação necessária."


class ForbiddenError(AppError):
    status_code, code, public_message = 403, "forbidden", "Sem permissão para esta operação."


class ConflictError(AppError):
    status_code, code, public_message = 409, "conflict", "Conflito com o estado atual do recurso."


class PlanLimitExceededError(AppError):
    status_code, code = 402, "plan_limit_exceeded"
    public_message = "O plano atual não permite esta operação."


class SubscriptionInactiveError(AppError):
    status_code, code = 402, "subscription_inactive"
    public_message = "A assinatura da empresa não está ativa."


class RateLimitedError(AppError):
    status_code, code, public_message = 429, "rate_limited", "Muitas requisições. Tente novamente em instantes."


# Mensagens genéricas para HTTPException "cruas" (ex.: 404 de rota, 405).
_GENERIC_HTTP_MESSAGES = {
    400: ("bad_request", "Requisição inválida."),
    401: ("unauthorized", "Autenticação necessária."),
    403: ("forbidden", "Sem permissão para esta operação."),
    404: ("not_found", "Recurso não encontrado."),
    405: ("method_not_allowed", "Método não permitido."),
    409: ("conflict", "Conflito com o estado atual do recurso."),
    413: ("payload_too_large", "Corpo da requisição muito grande."),
    415: ("unsupported_media_type", "Tipo de conteúdo não suportado."),
    422: ("unprocessable_entity", "Dados inválidos."),
    429: ("rate_limited", "Muitas requisições. Tente novamente em instantes."),
}


# --------------------------------------------------------------------------- #
# Utilitários
# --------------------------------------------------------------------------- #
def _request_id(request: Request) -> str:
    rid = getattr(request.state, "request_id", None)
    if rid:
        return rid
    # Não confia cegamente no cabeçalho do cliente (evita log injection).
    incoming = request.headers.get(REQUEST_ID_HEADER, "")
    rid = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
    request.state.request_id = rid
    return rid


def _log_context(request: Request, error_id: str) -> dict[str, Any]:
    """Contexto seguro para log: sem corpo, sem query string, sem Authorization."""
    state = request.state
    return {
        "error_id": error_id,
        "tenant_id": getattr(state, "tenant_id", None),
        "user_id": getattr(state, "user_id", None),
        "method": request.method,
        "path": request.url.path,  # sem query string (pode conter tokens/PII)
        "client_ip": request.client.host if request.client else None,
    }


def _response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    *,
    details: Any = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    error_id = _request_id(request)
    body: dict[str, Any] = {"error": {"code": code, "message": message, "error_id": error_id}}
    if details:
        body["error"]["details"] = details
    resp_headers = {
        REQUEST_ID_HEADER: error_id,
        "Cache-Control": "no-store",  # evita cache de respostas de erro por proxies/CDN
    }
    if headers:
        resp_headers.update(headers)
    return JSONResponse(status_code=status_code, content=body, headers=resp_headers)


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #
async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
    ctx = _log_context(request, _request_id(request))

    if isinstance(exc, CrossTenantAccessError):
        # Evento de segurança: loga com destaque, mas responde como 404 genérico.
        logger.warning("Tentativa de acesso cross-tenant", extra={"ctx": ctx, "security_event": True})
    elif exc.status_code >= 500:
        logger.error("Erro de domínio 5xx", extra={"ctx": ctx}, exc_info=exc)
    else:
        logger.info("Erro de domínio %s", exc.code, extra={"ctx": ctx})

    # Cross-tenant: ignora qualquer mensagem/extra customizados.
    if isinstance(exc, CrossTenantAccessError):
        return _response(request, 404, NotFoundError.code, NotFoundError.public_message)

    headers = {"Retry-After": str(exc.extra["retry_after"])} if "retry_after" in exc.extra else None
    details = {k: v for k, v in exc.extra.items() if k != "retry_after"} or None
    return _response(request, exc.status_code, exc.code, exc.public_message, details=details, headers=headers)


async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    ctx = _log_context(request, _request_id(request))
    level = logging.ERROR if exc.status_code >= 500 else logging.INFO
    logger.log(level, "HTTPException %s", exc.status_code, extra={"ctx": ctx})

    if exc.status_code >= 500:
        return _response(request, exc.status_code, "internal_error", "Erro interno. Informe o error_id ao suporte.")

    # Para 4xx NÃO repassa exc.detail: pode vir de libs/terceiros com informação interna.
    code, message = _GENERIC_HTTP_MESSAGES.get(exc.status_code, ("client_error", "Requisição inválida."))
    headers = {k: v for k, v in (exc.headers or {}).items() if k.lower() in {"www-authenticate", "retry-after", "allow"}}
    return _response(request, exc.status_code, code, message, headers=headers or None)


async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    ctx = _log_context(request, _request_id(request))
    logger.info("Falha de validação", extra={"ctx": ctx, "error_count": len(exc.errors())})

    # Devolve apenas local e mensagem. Nunca `input` ou `ctx` (podem conter senhas, PII, dados de negócio).
    details = [
        {
            "field": ".".join(str(p) for p in err.get("loc", ()) if p != "body"),
            "message": err.get("msg", "Valor inválido."),
            "type": err.get("type", "invalid"),
        }
        for err in exc.errors()[:50]  # limita o tamanho da resposta
    ]
    return _response(request, 422, "validation_error", "Dados inválidos.", details=details)


async def handle_db_error(request: Request, exc: Exception) -> JSONResponse:
    ctx = _log_context(request, _request_id(request))

    if IntegrityError is not None and isinstance(exc, IntegrityError):
        # Não expõe nome de constraint, tabela ou valores duplicados.
        logger.warning("Violação de integridade", extra={"ctx": ctx}, exc_info=exc)
        return _response(request, 409, "conflict", "Operação conflita com dados existentes.")

    if isinstance(exc, (OperationalError, SATimeoutError)):  # type: ignore[arg-type]
        logger.error("Banco indisponível/timeout", extra={"ctx": ctx}, exc_info=exc)
        return _response(
            request, 503, "service_unavailable",
            "Serviço temporariamente indisponível. Tente novamente.",
            headers={"Retry-After": "5"},
        )

    logger.error("Erro de banco não mapeado", extra={"ctx": ctx}, exc_info=exc)
    return _response(request, 500, "internal_error", "Erro interno. Informe o error_id ao suporte.")


async def handle_unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    """Último recurso: qualquer exceção não prevista vira 500 genérico."""
    ctx = _log_context(request, _request_id(request))
    # O stack trace vai SOMENTE para o log interno.
    logger.critical("Exceção não tratada", extra={"ctx": ctx}, exc_info=exc)
    return _response(request, 500, "internal_error", "Erro interno. Informe o error_id ao suporte.")


# --------------------------------------------------------------------------- #
# Registro
# --------------------------------------------------------------------------- #
def register_error_handlers(app: FastAPI) -> None:
    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        rid = _request_id(request)
        response = await call_next(request)
        response.headers.setdefault(REQUEST_ID_HEADER, rid)
        return response

    app.add_exception_handler(AppError, handle_app_error)
    app.add_exception_handler(StarletteHTTPException, handle_http_exception)
    app.add_exception_handler(RequestValidationError, handle_validation_error)
    if DBAPIError is not None:
        app.add_exception_handler(DBAPIError, handle_db_error)
    app.add_exception_handler(Exception, handle_unhandled_exception)


# --------------------------------------------------------------------------- #
# Exemplo de uso
# --------------------------------------------------------------------------- #
# app = FastAPI(debug=False)  # debug=True devolveria stack trace ao cliente
# register_error_handlers(app)
#
# @app.get("/invoices/{invoice_id}")
# async def get_invoice(invoice_id: int, request: Request):
#     invoice = await repo.get(invoice_id)          # consulta SEM filtro de tenant
#     if invoice is None:
#         raise NotFoundError()
#     if invoice.tenant_id != request.state.tenant_id:
#         raise CrossTenantAccessError()            # cliente vê 404; log registra o evento
#     return invoice