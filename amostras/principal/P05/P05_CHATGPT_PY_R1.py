from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

app= FastAPI()

# Em produção, injete estas dependências via configuração/container.
db_session: AsyncSession
redis: Redis


@app.get("/health")
async def health():
    services= {}

    # Banco de dados
    try:
        await db_session.execute(text("SELECT 1"))
        services["database"] = "ok"
    except Exception:
        services["database"] = "unavailable"

    # Cache
    try:
        await redis.ping()
        services["cache"] = "ok"
    except Exception:
        services["cache"] = "unavailable"

    healthy= all(status== "ok" for statusin services.values())

    return {
        "status": "ok" if healthyelse "degraded",
        "services": services,
    }