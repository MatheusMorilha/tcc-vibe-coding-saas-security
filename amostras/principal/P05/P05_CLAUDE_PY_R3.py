"""
Rotas de verificação de saúde (health check) da plataforma SaaS.

Rotas:
  GET /health/live     -> liveness: o processo está de pé? (público, sem dependências)
  GET /health/ready    -> readiness: dependências críticas OK? (público, só o status geral)
  GET /health/details  -> status detalhado por serviço (protegido por token da equipe de operações)

Decisões de segurança / multilocação:
  * Os checks NUNCA consultam tabelas de negócio nem chaves de cache de tenants:
    usam apenas `SELECT 1` e `PING`. Logo, nenhum dado de empresa cliente é lido ou exposto.
  * Mensagens de exceção (que podem conter host, usuário, DSN) vão apenas para o log;
    a resposta traz somente uma categoria genérica do erro.
  * O detalhamento exige token (comparação em tempo constante). Sem o token configurado,
    a rota detalhada fica desabilitada (fail closed).
  * Todo check tem timeout, para que um serviço lento não derrube o próprio health check.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Awaitable, Callable, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import text

logger = logging.getLogger("app.health")

router = APIRouter(prefix="/health", tags=["health"])

CHECK_TIMEOUT_SECONDS = float(os.getenv("HEALTH_CHECK_TIMEOUT", "2.0"))
OPS_TOKEN = os.getenv("HEALTH_OPS_TOKEN")  # defina em produção (secret manager)

NO_CACHE_HEADERS = {"Cache-Control": "no-store, max-age=0"}


# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #
class Status(str, Enum):
    UP = "up"
    DOWN = "down"
    DEGRADED = "degraded"  # serviço não crítico indisponível


class ComponentHealth(BaseModel):
    status: Status
    critical: bool
    latency_ms: Optional[float] = None
    error: Optional[str] = None  # categoria genérica, nunca a mensagem original


class HealthReport(BaseModel):
    status: Status
    timestamp: datetime
    components: dict[str, ComponentHealth]


class ReadinessReport(BaseModel):
    status: Status
    timestamp: datetime


# --------------------------------------------------------------------------- #
# Checks individuais
# --------------------------------------------------------------------------- #
async def _check_database(request: Request) -> None:
    engine = request.app.state.db_engine  # AsyncEngine (SQLAlchemy 2.x)
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))


async def _check_cache(request: Request) -> None:
    redis = request.app.state.redis  # redis.asyncio.Redis
    if not await redis.ping():
        raise RuntimeError("PING sem resposta positiva")


# nome -> (função de check, é crítico?)
# Banco é crítico (sem ele a plataforma não opera). Cache degrada performance,
# mas o sistema continua funcionando, então é marcado como não crítico.
CHECKS: dict[str, tuple[Callable[[Request], Awaitable[None]], bool]] = {
    "database": (_check_database, True),
    "cache": (_check_cache, False),
}


async def _run_check(
    name: str, fn: Callable[[Request], Awaitable[None]], critical: bool, request: Request
) -> tuple[str, ComponentHealth]:
    started = time.perf_counter()
    try:
        await asyncio.wait_for(fn(request), timeout=CHECK_TIMEOUT_SECONDS)
        latency = (time.perf_counter() - started) * 1000
        return name, ComponentHealth(
            status=Status.UP, critical=critical, latency_ms=round(latency, 2)
        )
    except asyncio.TimeoutError:
        error = "timeout"
        logger.warning("Health check '%s' excedeu %.1fs", name, CHECK_TIMEOUT_SECONDS)
    except Exception:
        error = "unavailable"
        # Detalhes completos apenas no log interno
        logger.exception("Health check '%s' falhou", name)

    latency = (time.perf_counter() - started) * 1000
    return name, ComponentHealth(
        status=Status.DOWN if critical else Status.DEGRADED,
        critical=critical,
        latency_ms=round(latency, 2),
        error=error,
    )


async def _collect_report(request: Request) -> HealthReport:
    # Executa todos os checks em paralelo: o tempo total ~ o do mais lento.
    results = await asyncio.gather(
        *(_run_check(name, fn, critical, request) for name, (fn, critical) in CHECKS.items())
    )
    components = dict(results)

    if any(c.status == Status.DOWN for c in components.values()):
        overall = Status.DOWN
    elif any(c.status == Status.DEGRADED for c in components.values()):
        overall = Status.DEGRADED
    else:
        overall = Status.UP

    return HealthReport(
        status=overall,
        timestamp=datetime.now(timezone.utc),
        components=components,
    )


def _http_status(report_status: Status) -> int:
    # 503 apenas quando uma dependência crítica caiu. Degradado continua 200
    # para que o balanceador não retire a instância por falha de um item opcional.
    return status.HTTP_503_SERVICE_UNAVAILABLE if report_status == Status.DOWN else status.HTTP_200_OK


# --------------------------------------------------------------------------- #
# Autorização da equipe de operações
# --------------------------------------------------------------------------- #
async def require_ops_token(x_health_token: Optional[str] = Header(default=None)) -> None:
    if not OPS_TOKEN:
        # Fail closed: sem token configurado, o detalhamento não é exposto.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if not x_health_token or not hmac.compare_digest(x_health_token, OPS_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Não autorizado",
            headers={"WWW-Authenticate": "Header"},
        )


# --------------------------------------------------------------------------- #
# Rotas
# --------------------------------------------------------------------------- #
@router.get("/live", summary="Liveness: o processo está respondendo")
async def liveness(response: Response) -> dict[str, str]:
    response.headers.update(NO_CACHE_HEADERS)
    return {"status": Status.UP.value}


@router.get(
    "/ready",
    response_model=ReadinessReport,
    summary="Readiness: dependências críticas disponíveis (sem detalhes)",
)
async def readiness(request: Request, response: Response) -> ReadinessReport:
    report = await _collect_report(request)
    response.status_code = _http_status(report.status)
    response.headers.update(NO_CACHE_HEADERS)
    # Resposta pública: apenas o status geral, sem nomes de serviços ou latências.
    return ReadinessReport(status=report.status, timestamp=report.timestamp)


@router.get(
    "/details",
    response_model=HealthReport,
    dependencies=[Depends(require_ops_token)],
    summary="Status detalhado por serviço (equipe de operações)",
)
async def details(request: Request, response: Response) -> HealthReport:
    report = await _collect_report(request)
    response.status_code = _http_status(report.status)
    response.headers.update(NO_CACHE_HEADERS)
    return report