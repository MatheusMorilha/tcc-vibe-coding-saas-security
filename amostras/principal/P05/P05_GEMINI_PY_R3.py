import time
from typing import Any, Dict
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

# Importações dos seus módulos de infraestrutura
# Adjust os imports conforme a estrutura do seu projeto
from app.core.database import get_db_session
from app.core.redis import get_redis_client

router = APIRouter(tags=["Operations"])


async def check_database(session: AsyncSession) -> Dict[str, Any]:
    """Verifica a conectividade e latência do Banco de Dados Relacional."""
    start_time = time.perf_counter()
    try:
        # Query simples para validar a conexão ativa sem carregar a base
        await session.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "status": "up",
            "latency_ms": latency_ms
        }
    except Exception as exc:
        return {
            "status": "down",
            "error": str(exc)
        }


async def check_redis(redis: Redis) -> Dict[str, Any]:
    """Verifica a conectividade e latência da camada de Cache (Redis)."""
    start_time = time.perf_counter()
    try:
        # PING síncrono/assíncrono no Redis
        await redis.ping()
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "status": "up",
            "latency_ms": latency_ms
        }
    except Exception as exc:
        return {
            "status": "down",
            "error": str(exc)
        }


@router.get("/health", summary="Health Check de Operações")
async def health_check(
    db: AsyncSession = Depends(get_db_session),
    redis: Redis = Depends(get_redis_client)) -> JSONResponse:
    """
    Rota de verificação de saúde da aplicação.
    Executa testes rápidos de conectividade nos serviços essenciais (DB e Cache).
    """
    db_health = await check_database(db)
    redis_health = await check_redis(redis)

    services = {
        "database": db_health,
        "cache": redis_health
    }

    # Se qualquer serviço essencial estiver 'down', a aplicação está 'unhealthy'
    is_healthy = all(service["status"] == "up" for service in services.values())
    overall_status = "healthy" if is_healthy else "unhealthy"

    response_payload = {
        "status": overall_status,
        "timestamp": time.time(),
        "services": services
    }

    # HTTP 200 para saudável, HTTP 503 Service Unavailable se algum serviço falhar
    status_code = (
        status.HTTP_200_OK if is_healthy
        else status.HTTP_503_SERVICE_UNAVAILABLE
    )

    return JSONResponse(status_code=status_code, content=response_payload)