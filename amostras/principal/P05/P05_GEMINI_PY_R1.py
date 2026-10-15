import time
from typing import Any, Dict
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

# Importe suas dependências reais da aplicação
# from app.db.session import get_db
# from app.cache.redis import get_redis

router = APIRouter(prefix="/health", tags=["Operations"])

TIMEOUT_SECONDS = 2.0


async def check_database(db: AsyncSession) -> Dict[str, Any]:
    """Verifica a conectividade e o tempo de resposta do Banco de Dados."""
    start_time = time.perf_counter()
    try:
        # Query leve para testar conexão sem sobrecarregar a base multilocatária
        await db.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "status": "healthy",
            "latency_ms": latency_ms,
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
        }


async def check_redis(redis: Redis) -> Dict[str, Any]:
    """Verifica a conectividade e o tempo de resposta do Cache (Redis)."""
    start_time = time.perf_counter()
    try:
        pong = await redis.ping()
        if not pong:
            raise Exception("PONG não retornado pelo Redis.")
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "status": "healthy",
            "latency_ms": latency_ms,
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
        }


@router.get("/live", status_code=status.HTTP_200_OK)
async def liveness_probe():
    """Liveness Probe: Indica se a aplicação Python está rodando.
    Utilizado pelo Kubernetes/Load Balancer para saber se precisa reiniciar o container.
    """
    return {"status": "alive"}


@router.get("/ready")
@router.get("")
async def readiness_probe(
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),):
    """Readiness Probe: Verifica se as dependências críticas (DB e Cache) estão prontas.
    Utilizado pela equipe de operações e gateways para roteamento de tráfego.
    """
    # Executa as checagens das dependências
    db_health = await check_database(db)
    redis_health = await check_redis(redis)

    checks = {
        "database": db_health,
        "cache": redis_health,
    }

    # Se qualquer serviço crítico falhar, o status geral passa a ser 'unhealthy'
    is_healthy = all(check["status"] == "healthy" for check in checks.values())

    response_payload = {
        "status": "healthy" if is_healthy else "unhealthy",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "checks": checks,
    }

    http_status = status.HTTP_200_OK if is_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(content=response_payload, status_code=http_status)