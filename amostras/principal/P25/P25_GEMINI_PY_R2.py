import json
import logging
from typing import Callable
from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Configuração básica de log para saída em formato JSON/Estruturado
logger = logging.getLogger("auth_audit")
logger.setLevel(logging.WARNING)

# Evita duplicação de handlers se reimportado
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '{"time": "%(asctime)s", "level": "%(levelname)s", "event": "%(message)s"}'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


class FailedAuthLoggerMiddleware(BaseHTTPMiddleware):
    """
    Middleware responsável por capturar e registrar no log todas as
    tentativas de autenticação que resultarem em falha (HTTP status 400 a 499).
    """

    def __init__(self, app: FastAPI, auth_path: str = "/api/v1/auth/login"):
        super().__init__(app)
        self.auth_path = auth_path

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Intercepta apenas o endpoint específico de login/autenticação via POST
        if request.url.path == self.auth_path and request.method == "POST":
            # Leitura do corpo da requisição
            body_bytes = await request.body()

            # Recria o stream do corpo para que o endpoint de login possa lê-lo normalmente depois
            async def receive():
                return {"type": "http.request", "body": body_bytes}

            request = Request(request.scope, receive=receive)

            # Executa a requisição até o endpoint final
            response = await call_next(request)

            # Se o status indicar falha de autenticação (ex: 401 Unauthorized, 400 Bad Request, 403 Forbidden)
            if 400 <= response.status_code < 500:
                await self._log_failed_attempt(request, body_bytes, response.status_code)

            return response

        # Para outros endpoints ou métodos, segue o fluxo normal
        return await call_next(request)

    async def _log_failed_attempt(self, request: Request, body_bytes: bytes, status_code: int):
        """Prepara e sanitiza os dados antes de gravar o log."""
        payload_data = {}

        try:
            if body_bytes:
                payload_data = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            payload_data = {"raw_body": "Incapaz de decodificar JSON"}

        # MASCARAMENTO DE DADOS SENSÍVEIS (LGPD / Segurança)
        # Nunca grave senhas, PINs ou tokens em logs de texto puro.
        sensitive_fields = {"password", "senha", "secret", "token", "access_token"}
        sanitized_payload = {
            k: ("*** REDACTED ***" if k.lower() in sensitive_fields else v)
            for k, v in payload_data.items()
        }

        # Contexto completo do suporte
        audit_data = {
            "path": request.url.path,
            "method": request.method,
            "status_code": status_code,
            "client_ip": request.client.host if request.client else "Desconhecido",
            "user_agent": request.headers.get("user-agent", "N/A"),
            "tenant_domain": request.headers.get("x-tenant-id") or request.headers.get("host"),
            "payload_sent": sanitized_payload,
        }

        logger.warning(json.dumps(audit_data, ensure_ascii=False))


# =====================================================================
# Exemplo de Aplicação FastAPI utilizando o Middleware
# =====================================================================

app = FastAPI(title="SaaS Multi-tenant Platform")

# Registra o middleware apontando para a rota de login
app.add_middleware(FailedAuthLoggerMiddleware, auth_path="/api/v1/auth/login")


@app.post("/api/v1/auth/login")
async def login(request: Request):
    data = await request.json()
    email = data.get("email")
    password = data.get("password")

    # Simulação de regra de autenticação
    if email != "admin@empresa.com" or password != "senha_correta":
        return Response(
            content=json.dumps({"detail": "Credenciais inválidas"}),
            status_code=401,
            media_type="application/json"
        )

    return {"message": "Login efetuado com sucesso", "token": "jwt_token_exemplo"}