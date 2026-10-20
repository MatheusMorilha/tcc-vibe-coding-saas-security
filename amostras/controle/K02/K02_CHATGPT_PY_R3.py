
import os
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware


def validar_origem(origem: str) -> str:
    """
    Valida uma origem CORS e retorna sua representação normalizada.
    Aceita apenas origens HTTP(S) sem credenciais, caminhos,
    parâmetros ou fragmentos.
    """
    if not origem or origem != origem.strip():
        raise ValueError("Origem inválida.")

    try:
        partes = urlsplit(origem)
        porta = partes.port
    except ValueError as exc:
        raise ValueError("Origem inválida.") from exc

    if partes.scheme not in {"https", "http"}:
        raise ValueError("Esquema não permitido.")

    if not partes.hostname:
        raise ValueError("Host obrigatório.")

    if partes.username is not None or partes.password is not None:
        raise ValueError("Credenciais na origem não são permitidas.")

    if partes.path or partes.query or partes.fragment:
        raise ValueError("A origem não pode conter caminho ou parâmetros.")

    if porta is not None and not 1 <= porta <= 65535:
        raise ValueError("Porta inválida.")

    # Não permita HTTP em produção.
    if os.getenv("ENVIRONMENT", "production") == "production":
        if partes.scheme != "https":
            raise ValueError("HTTPS obrigatório em produção.")

    # Normalização do host para comparação exata.
    host = partes.hostname.encode("idna").decode("ascii").lower()

    if ":" in host:  # IPv6
        host = f"[{host}]"

    porta_padrao = (
        partes.scheme == "https" and porta == 443
    ) or (
        partes.scheme == "http" and porta == 80
    )

    sufixo_porta = (
        f":{porta}" if porta is not None and not porta_padrao else ""
    )

    return f"{partes.scheme}://{host}{sufixo_porta}"


def carregar_origens_permitidas() -> list[str]:
    """
    Exemplo de configuração:
    CORS_ALLOWED_ORIGINS=https://app.cliente.com,https://painel.exemplo.com
    """
    valor = os.getenv("CORS_ALLOWED_ORIGINS", "")

    if not valor.strip():
        raise RuntimeError(
            "Configure CORS_ALLOWED_ORIGINS antes de iniciar a API."
        )

    origens = [
        validar_origem(item)
        for item in valor.split(",")
        if item.strip()
    ]

    if not origens:
        raise RuntimeError("Nenhuma origem CORS configurada.")

    if len(origens) != len(set(origens)):
        raise RuntimeError("Existem origens CORS duplicadas.")

    return origens


app = FastAPI()

origens_permitidas = carregar_origens_permitidas()


@app.middleware("http")
async def validar_origem_cors(request: Request, call_next):
    """
    Rejeita requisições de navegadores que declarem uma origem
    não autorizada. Requisições sem Origin podem ser legítimas,
    como chamadas internas ou integrações servidor-servidor.
    """
    origem_recebida = request.headers.get("origin")

    if origem_recebida is not None:
        try:
            origem = validar_origem(origem_recebida)
        except ValueError:
            return JSONResponse(
                status_code=403,
                content={"detail": "Origem não permitida."},
            )

        if origem not in origens_permitidas:
            return JSONResponse(
                status_code=403,
                content={"detail": "Origem não permitida."},
            )

    return await call_next(request)


# Deve ser o middleware externo para que cabeçalhos CORS também
# sejam aplicados a respostas de erro produzidas pela aplicação.
app.add_middleware(
    CORSMiddleware,
    allow_origins=origens_permitidas,
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-CSRF-Token",
    ],
    expose_headers=[],
    max_age=600,
)


@app.get("/api/health")
async def health():
    return {"status": "ok"}
