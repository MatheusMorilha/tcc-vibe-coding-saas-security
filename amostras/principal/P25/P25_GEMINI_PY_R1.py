import json
import logging

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Configuração básica do logger do sistema
logger = logging.getLogger("auth_audit")
logger.setLevel(logging.INFO)

handler = logging.StreamHandler()
handler.setFormatter(
    logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
)
logger.addHandler(handler)


class FailedAuthLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware responsável por registrar tentativas de autenticação malsucedidas
    para suporte e auditoria em ambiente SaaS multitenant.
    """

    def __init__(
        self, app: FastAPI, auth_path: str = "/api/v1/auth/login") -> None:
        super().__init__(app)
        self.auth_path = auth_path

    async def dispatch(self, request: Request, call_next) -> Response:
        # Intercepta apenas requisições POST para a rota de autenticação
        if request.url.path == self.auth_path and request.method == "POST":
            # 1. Lê o corpo da requisição sem consumi-lo de forma destrutiva
            body_bytes = await request.body()

            # Função customizada para que o endpoint subsequente consiga ler o body novamente
            async def receive():
                return {"type": "http.request", "body": body_bytes}

            request = Request(request.scope, receive=receive)

            # 2. Processa a requisição no fluxo normal da aplicação
            response = await call_next(request)

            # 3. Verifica se a autenticação falhou (ex: 401 Unauthorized ou 400 Bad Request)
            if response.status_code in (401, 400):
                await self._log_failed_attempt(request, body_bytes, response)

            return response

        return await call_next(request)

    async def _log_failed_attempt(
        self, request: Request, body_bytes: bytes, response: Response) -> None:
        """Extrai os metadados da requisição e grava o log estruturado."""
        payload = {}
        if body_bytes:
            try:
                payload = json.loads(body_bytes.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                payload = {"raw": "<dados não serializáveis em JSON>"}

        # Sanitização: REMOVE a senha antes de salvar nos logs por segurança (compliance / LGPD)
        if isinstance(payload, dict):
            payload.pop("password", None)
            payload.pop("senha", None)

        # Captura de identificadores e contexto do SaaS
        client_ip = request.client.host if request.client else "desconhecido"
        tenant_id = (
            request.headers.get("X-Tenant-ID")
            or payload.get("tenant_id")
            or payload.get("domain")
            or "não especificado"
        )
        user_agent = request.headers.get("user-agent", "desconhecido")
        username_attempt = (
            payload.get("email")
            or payload.get("username")
            or "não informado"
        )

        log_data = {
            "event": "FAILED_AUTHENTICATION_ATTEMPT",
            "status_code": response.status_code,
            "tenant_id": tenant_id,
            "username_attempt": username_attempt,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "path": request.url.path,
            "request_payload": payload,
        }

        # Registra em formato JSON estruturado (ideal para soluções como Datadog, ELK, CloudWatch)
        logger.warning(json.dumps(log_data))