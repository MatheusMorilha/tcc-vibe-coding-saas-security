import json
import logging
from typing import Callable
from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Configuração do logger da aplicação
logger = logging.getLogger("auth_audit")
logger.setLevel(logging.INFO)

# Handler de exemplo apontando para stdout (pode ser redirecionado para Datadog, ELK, etc.)
handler = logging.StreamHandler()
formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s - %(name)s - %(message)s'
)
handler.setFormatter(formatter)
logger.addHandler(handler)


class FailedAuthLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware responsável por interceptar requisições nos endpoints de autenticação
    e registrar em log apenas as tentativas que resultaram em falhas (401/403).
    """

    def __init__(self, app: FastAPI, auth_endpoints: list[str] = None):
        super().__init__(app)
        # Endpoints monitorados para auditoria de login
        self.auth_endpoints = auth_endpoints or ["/api/v1/auth/login", "/api/v1/auth/token"]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Processa apenas requisições POST direcionadas aos endpoints de autenticação
        if request.url.path not in self.auth_endpoints or request.method != "POST":
            return await call_next(request)

        # Copia o corpo da requisição sem consumir a stream de forma destrutiva
        body_bytes = await request.body()

        # Função auxiliar para re-injetar a stream do corpo para o endpoint consumir normalmente
        async def receive():
            return {"type": "http.request", "body": body_bytes}

        request = Request(request.scope, receive=receive)

        # Processa a requisição na aplicação
        response = await call_next(request)

        # Intercepta falhas de autenticação (401 Unauthorized ou 403 Forbidden)
        if response.status_code in (401, 403):
            await self._log_failed_attempt(request, body_bytes, response.status_code)

        return response

    async def _log_failed_attempt(self, request: Request, body_bytes: bytes, status_code: int):
        """
        Extrai os dados da tentativa e registra o log com sanitização de credenciais sensíveis.
        """
        client_ip = request.client.host if request.client else "Unknown"
        user_agent = request.headers.get("user-agent", "Unknown")

        # Tenta decodificar o payload enviado
        try:
            payload = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            payload = {"raw_body": body_bytes.decode("utf-8", errors="ignore")}

        # Sanitização: remove senhas do log para conformidade de segurança e LGPD
        sanitized_payload = self._sanitize_payload(payload)

        log_data = {
            "event": "FAILED_AUTHENTICATION_ATTEMPT",
            "path": request.url.path,
            "status_code": status_code,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "headers": {
                "x-forwarded-for": request.headers.get("x-forwarded-for"),
                "host": request.headers.get("host")
            },
            "payload": sanitized_payload
        }

        logger.warning(f"Tentativa de login malsucedida: {json.dumps(log_data)}")

    def _sanitize_payload(self, payload: dict) -> dict:
        """
        Oculta dados sensíveis como senhas antes de gravar no log.
        """
        if not isinstance(payload, dict):
            return payload

        sanitized = payload.copy()
        sensitive_fields = ["password", "senha", "secret", "token", "access_token"]

        for key in sanitized:
            if key.lower() in sensitive_fields:
                sanitized[key] = "********"

        return sanitized

app = FastAPI(title="SaaS Multi-tenant Platform")

# Registro do Middleware
app.add_middleware(
    FailedAuthLoggingMiddleware,
    auth_endpoints=["/api/v1/auth/login"]
)

@app.post("/api/v1/auth/login")
async def login(request: Request):
    # Exemplo de rota de login simulando falha de credencial inválida
    return Response(
        content=json.dumps({"detail": "Credenciais inválidas"}),
        status_code=401,
        media_type="application/json"
    )