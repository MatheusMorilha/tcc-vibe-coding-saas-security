import logging
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional


logger= logging.getLogger(__name__)


@dataclass
class ApiError:
    status_code: int
    code: str
    message: str


class GlobalErrorHandler:
    """
    Tratador global de exceções não capturadas da API.

    Responsabilidades:
    - Converter exceções em respostas HTTP padronizadas.
    - Não expor stack traces ou detalhes internos ao cliente.
    - Gerar um request_id para correlação com logs.
    - Registrar detalhes técnicos exclusivamente no servidor.
    - Evitar vazamento de informações entre tenants.
    """

    def __init__(self)-> None:
        self._unexpected_error= ApiError(
            status_code=500,
            code="INTERNAL_SERVER_ERROR",
            message="Ocorreu um erro interno no servidor.",
        )

    def handle(
        self,
        exception: Exception,
        *,
        tenant_id: Optional[str] = None,
        user_id: Optional[str] = None,
    )-> tuple[Dict[str, Any], int, Dict[str, str]]:
        request_id= str(uuid.uuid4())

        logger.exception(
            "Erro não capturado na API",
            extra={
                "request_id": request_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "exception_type":type(exception).__name__,
            },
        )

        error= self._map_exception(exception)

        response= {
            "error": {
                "code": error.code,
                "message": error.message,
                "request_id": request_id,
            }
        }

        headers= {
            "Content-Type": "application/json",
            "X-Request-ID": request_id,
        }

        return response, error.status_code, headers

    @staticmethod
    def _map_exception(exception: Exception)-> ApiError:
        """
        Mapeia exceções conhecidas para respostas públicas.
        Exceções desconhecidas nunca têm seus detalhes retornados.
        """

        if isinstance(exception,PermissionError):
            return ApiError(
                status_code=403,
                code="FORBIDDEN",
                message="Você não tem permissão para realizar esta operação.",
            )

        if isinstance(exception,ValueError):
            return ApiError(
                status_code=400,
                code="INVALID_REQUEST",
                message="Os dados enviados são inválidos.",
            )

        if isinstance(exception,KeyError):
            return ApiError(
                status_code=400,
                code="MISSING_FIELD",
                message="Existe um campo obrigatório ausente na requisição.",
            )

        return ApiError(
            status_code=500,
            code="INTERNAL_SERVER_ERROR",
            message="Ocorreu um erro interno no servidor.",
        )


error_handler= GlobalErrorHandler()


def handle_uncaught_exception(
    exception: Exception,
    *,
    tenant_id: Optional[str] = None,
    user_id: Optional[str] = None,
):
    """
    Ponto único de entrada para o middleware global da API.
    """

    return error_handler.handle(
        exception,
        tenant_id=tenant_id,
        user_id=user_id,
    )