import time
import logging
from typing import Dict, Any
from fastapi import APIRouter, status, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import redis.asyncio as redis

# Configuração de Logs
logger = logging.getLogger("health_check")

router = APIRouter(prefix="/health", tags=["Operations"])

# Instância global do Redis (ou injetada via dependência)
redis_client = redis.Redis(host="localhost", port=6379, db=0, socket_timeout=2.0)


async def check_database(db: AsyncSession) -> Dict[str, Any]:
    """Valida a conexão com o banco de dados executando uma consulta simples."""
    start_time = time.perf_counter()
    try:
        # SELECT 1 garante validação rápida da conexão sem overhead de IO
        await db.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {"status": "up", "latency_ms": latency_ms}
    except Exception as exc:
        logger.error(f"Falha na verificação do banco de dados: {exc}")
        return {"status": "down", "error": "Database connection failed"}


async def check_redis() -> Dict[str, Any]:
    """Valida a conexão com o serviço de cache (Redis)."""
    start_time = time.perf_counter()
    try:
        # PING rápido para verificar disponibilidade do cache
        pong = await redis_client.ping()
        if not pong:
            raise ConnectionError("Redis PING retornou Falso")
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {"status": "up", "latency_ms": latency_ms}
    except Exception as exc:
        logger.error(f"Falha na verificação do Redis: {exc}")
        return {"status": "down", "error": "Cache service unavailable"}


@router.get(
    "",
    summary="Verificação de Saúde do Sistema",
    description="Retorna o status operacional da API e suas dependências (Database, Cache).",)
async def health_check(response: Response, db: AsyncSession) -> Dict[str, Any]:
    """
    Endpoint de verificação de saúde da aplicação.
    - Status HTTP 200: Todos os serviços essenciais estão funcionando (healthy).
    - Status HTTP 503: Um ou mais serviços críticos falharam (unhealthy).
    """
    # Executa as verificações
    db_health = await check_database(db)
    redis_health = await check_redis()

    # Avalia se a aplicação está totalmente operacional
    services = {
        "database": db_health,
        "cache": redis_health,
    }

    is_healthy = all(service["status"] == "up" for service in services.values())

    # Formata a resposta padrão da API
    payload = {
        "status": "healthy" if is_healthy else "unhealthy",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "services": services,
    }

    # Se alguma dependência crítica cair, define o status HTTP para 503 Service Unavailable
    if not is_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return payload