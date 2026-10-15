"""
Rotas de verificação de saúde da aplicação (SaaS multilocatário).

- GET /health/live  -> liveness: público, sem dependências, resposta mínima.
- GET /health/ready -> readiness: status detalhado de BD e cache, restrito à
                       equipe de operações (token no header X-Health-Token).

Decisões de segurança/multilocação:
- As verificações NÃO usam tabelas de negócio nem contexto de tenant
  (apenas `SELECT 1` e `PING`), logo nunca tocam dados de nenhuma empresa.
- Mensagens de erro internas (host, credenciais, stack) nunca vão na resposta;
  são registradas apenas nos logs.
- Cada verificação tem timeout próprio e roda em paralelo, para que uma
  dependência travada não derrube o próprio endpoint.
"""

import asyncio
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Awaitable, Callable, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

logger = logging.getLogger("app.health")

# --------------------------------------------------------------------------- #
# Configuração (variáveis de ambiente)
# --------------------------------------------------------------------------- #
DATABASE_URL = os.environ["DATABASE_URL"]  # ex.: postgresql+asyncpg://...
REDIS_URL = os.environ["REDIS_URL"]  # ex.: redis://cache:6379/0
HEALTH_TOKEN = os.environ["HEALTH_CHECK_TOKEN"]  # segredo da equipe de operações
CHECK_TIMEOUT_SECONDS = float(os.getenv("HEALTH_CHECK_TIMEOUT", "2.0"))
APP_VERSION = os.getenv("APP_VERSION", "unknown")

_started_at = time.monotonic()

# Em produção, reutilize o engine/cliente já criados pela aplicação
# (injeção de dependência) em vez de instanciá-los aqui.
_engine: AsyncEngine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
_redis: Redis = Redis.from_url(REDIS_URL, socket_connect_timeout=CHECK_TIMEOUT_SECONDS)

# --------------------------------------------------------------------------- #
# Modelos de resposta
# --------------------------------------------------------------------------- #
DependencyState = Literal["up", "down"]
OverallState = Literal["ok", "degraded", "unavailable"]


class DependencyStatus(BaseModel):
    status: DependencyState
    critical: bool
    latency_ms: float | None = None
    error: str | None = None  # código genérico, nunca a mensagem da exceção


class HealthReport(BaseModel):
    status: OverallState
    version: str
    uptime_seconds: int
    checked_at: datetime
    dependencies: dict[str, DependencyStatus]


# --------------------------------------------------------------------------- #
# Verificações individuais
# --------------------------------------------------------------------------- #
async def _check_database() -> None:
    async with _engine.connect() as conn:
        await conn.execute(text("SELECT 1"))


async def _check_cache() -> None:
    if not await _redis.ping():
        raise RuntimeError("PING sem resposta positiva")


# nome -> (função de verificação, é crítica?)
# Banco é crítico (sem ele a plataforma não opera).
# Cache é não crítico: sua queda gera "degraded", não "unavailable".
CHECKS: dict[str, tuple[Callable[[], Awaitable[None]], bool]] = {
    "database": (_check_database, True),
    "cache": (_check_cache, False),
}


async def _run_check(
    name: str, fn: Callable[[], Awaitable[None]], critical: bool
) -> tuple[str, DependencyStatus]:
    started = time.perf_counter()
    try:
        await asyncio.wait_for(fn(), timeout=CHECK_TIMEOUT_SECONDS)
        latency = round((time.perf_counter() - started) * 1000, 2)
        return name, DependencyStatus(status="up", critical=critical, latency_ms=latency)
    except asyncio.TimeoutError:
        logger.error("Health check '%s' excedeu o timeout de %ss", name, CHECK_TIMEOUT_SECONDS)
        return name, DependencyStatus(status="down", critical=critical, error="timeout")
    except Exception:
        # Detalhes completos apenas no log; resposta traz código genérico.
        logger.exception("Health check '%s' falhou", name)
        return name, DependencyStatus(status="down", critical=critical, error="unreachable")


# --------------------------------------------------------------------------- #
# Autenticação da equipe de operações
# --------------------------------------------------------------------------- #
async def require_ops_token(x_health_token: str | None = Header(default=None)) -> None:
    # compare_digest evita ataques de timing na comparação do segredo.
    if not x_health_token or not secrets.compare_digest(x_health_token, HEALTH_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Não autorizado",
            headers={"WWW-Authenticate": "X-Health-Token"},
        )


# --------------------------------------------------------------------------- #
# Rotas
# --------------------------------------------------------------------------- #
router = APIRouter(prefix="/health", tags=["Health"])


@router.get("/live", summary="Liveness: o processo está de pé?")
async def liveness(response: Response) -> dict[str, str]:
    response.headers["Cache-Control"] = "no-store"
    return {"status": "ok"}


@router.get(
    "/ready",
    response_model=HealthReport,
    summary="Readiness: estado detalhado das dependências (uso interno)",
    dependencies=[Depends(require_ops_token)],
    responses={503: {"model": HealthReport, "description": "Dependência crítica indisponível"}},
)
async def readiness(response: Response) -> HealthReport:
    response.headers["Cache-Control"] = "no-store"

    results = await asyncio.gather(
        *(_run_check(name, fn, critical) for name, (fn, critical) in CHECKS.items())
    )
    dependencies = dict(results)

    if any(d.status == "down" and d.critical for d in dependencies.values()):
        overall: OverallState = "unavailable"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    elif any(d.status == "down" for d in dependencies.values()):
        overall = "degraded"  # segue 200: serviço opera, mas com ressalvas
    else:
        overall = "ok"

    return HealthReport(
        status=overall,
        version=APP_VERSION,
        uptime_seconds=int(time.monotonic() - _started_at),
        checked_at=datetime.now(timezone.utc),
        dependencies=dependencies,
    )


# Uso na aplicação principal:
#   from fastapi import FastAPI
#   from health import router as health_router
#   app = FastAPI()
#   app.include_router(health_router)