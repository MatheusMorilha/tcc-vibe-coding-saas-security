"""
Rotas de verificação de saúde (health check) para uso da equipe de operações.

Decisões de projeto relevantes para uma plataforma SaaS multilocatária:

* As verificações são GLOBAIS da aplicação: nunca consultam tabelas de negócio
  nem recebem/usam contexto de empresa (tenant). Usam apenas `SELECT 1` e `PING`,
  portanto não podem vazar nem tocar dados de nenhum cliente.
* `/health/live`  -> público e mínimo (liveness: o processo está de pé?).
* `/health/ready` -> detalhado (readiness: dependências OK?), protegido por token
  de operações. Falha fechada: sem token configurado no servidor, nega acesso.
* Nenhuma mensagem de exceção, host, versão ou string de conexão é devolvida;
  detalhes de erro vão apenas para o log.
* Cada verificação tem timeout e roda em paralelo, para que uma dependência
  travada não derrube o próprio endpoint de monitoramento.
* Respostas nunca são cacheadas.

Pré-requisitos (configurados no startup da aplicação):
    app.state.db_engine -> sqlalchemy.ext.asyncio.AsyncEngine
    app.state.redis     -> redis.asyncio.Redis
Variáveis de ambiente:
    HEALTH_OPS_TOKEN        token exigido no cabeçalho X-Ops-Token
    HEALTH_CHECK_TIMEOUT    timeout por verificação, em segundos (padrão: 2)

Uso:
    app.include_router(health.router)
"""

import asyncio
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Awaitable, Callable, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import text

logger = logging.getLogger("app.health")

router = APIRouter(prefix="/health", tags=["Operações"])

CHECK_TIMEOUT_SECONDS = float(os.getenv("HEALTH_CHECK_TIMEOUT", "2"))

# Dependências cuja falha torna a aplicação indisponível (HTTP 503).
# As demais, ao falhar, resultam em estado "degraded" (HTTP 200).
CRITICAL_DEPENDENCIES = {"database"}

NO_STORE_HEADERS = {"Cache-Control": "no-store, max-age=0", "Pragma": "no-cache"}


# --------------------------------------------------------------------------- #
# Modelos de resposta
# --------------------------------------------------------------------------- #
class DependencyStatus(BaseModel):
    status: Literal["up", "down"]
    latency_ms: float


class LivenessResponse(BaseModel):
    status: Literal["ok"]


class ReadinessResponse(BaseModel):
    status: Literal["ok", "degraded", "unhealthy"]
    checked_at: datetime
    dependencies: dict[str, DependencyStatus]


# --------------------------------------------------------------------------- #
# Autenticação da equipe de operações
# --------------------------------------------------------------------------- #
async def require_ops_token(x_ops_token: str | None = Header(default=None)) -> None:
    expected = os.getenv("HEALTH_OPS_TOKEN")
    if not expected:
        # Falha fechada: endpoint detalhado indisponível se não houver token configurado.
        logger.error("HEALTH_OPS_TOKEN não configurado; acesso a /health/ready negado.")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso negado.")

    # Comparação em tempo constante para evitar timing attacks.
    if not x_ops_token or not secrets.compare_digest(x_ops_token, expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso negado.")


# --------------------------------------------------------------------------- #
# Verificações individuais
# --------------------------------------------------------------------------- #
async def _check_database(request: Request) -> None:
    engine = request.app.state.db_engine
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))


async def _check_cache(request: Request) -> None:
    redis = request.app.state.redis
    if not await redis.ping():
        raise RuntimeError("Redis PING sem resposta positiva")


async def _run_check(
    name: str, check: Callable[[Request], Awaitable[None]], request: Request
) -> tuple[str, DependencyStatus]:
    start = time.perf_counter()
    try:
        await asyncio.wait_for(check(request), timeout=CHECK_TIMEOUT_SECONDS)
        state: Literal["up", "down"] = "up"
    except asyncio.TimeoutError:
        logger.error("Health check '%s' excedeu o timeout de %.1fs", name, CHECK_TIMEOUT_SECONDS)
        state = "down"
    except Exception:  # noqa: BLE001 - detalhes só no log, nunca na resposta
        logger.exception("Health check '%s' falhou", name)
        state = "down"

    latency_ms = round((time.perf_counter() - start) * 1000, 2)
    return name, DependencyStatus(status=state, latency_ms=latency_ms)


# --------------------------------------------------------------------------- #
# Rotas
# --------------------------------------------------------------------------- #
@router.get("/live", response_model=LivenessResponse, summary="Liveness (público)")
async def liveness(response: Response) -> LivenessResponse:
    """Indica apenas que o processo está respondendo. Não toca dependências."""
    response.headers.update(NO_STORE_HEADERS)
    return LivenessResponse(status="ok")


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness com status das dependências (restrito à operação)",
    dependencies=[Depends(require_ops_token)],
    responses={503: {"model": ReadinessResponse, "description": "Dependência crítica indisponível"}},
)
async def readiness(request: Request, response: Response) -> ReadinessResponse:
    """
    Verifica, em paralelo, banco de dados e cache.

    * 200 / "ok":        todas as dependências disponíveis.
    * 200 / "degraded":  alguma dependência não crítica indisponível.
    * 503 / "unhealthy": alguma dependência crítica indisponível.
    """
    results = await asyncio.gather(
        _run_check("database", _check_database, request),
        _run_check("cache", _check_cache, request),
    )
    dependencies = dict(results)

    failed = {name for name, dep in dependencies.items() if dep.status == "down"}
    if failed & CRITICAL_DEPENDENCIES:
        overall: Literal["ok", "degraded", "unhealthy"] = "unhealthy"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    elif failed:
        overall = "degraded"
    else:
        overall = "ok"

    response.headers.update(NO_STORE_HEADERS)
    return ReadinessResponse(
        status=overall,
        checked_at=datetime.now(timezone.utc),
        dependencies=dependencies,
    )