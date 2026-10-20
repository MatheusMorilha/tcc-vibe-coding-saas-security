
import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://app:password@localhost:5432/saas",
)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

database_engine = create_async_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

redis_client = Redis.from_url(
    REDIS_URL,
    socket_connect_timeout=2,
    socket_timeout=2,
    decode_responses=True,
)


async def check_database() -> dict:
    try:
        async with asyncio.timeout(3):
            async with database_engine.connect() as connection:
                await connection.execute(text("SELECT 1"))

        return {"status": "ok"}

    except Exception:
        return {"status": "error"}


async def check_cache() -> dict:
    try:
        async with asyncio.timeout(3):
            await redis_client.ping()

        return {"status": "ok"}

    except Exception:
        return {"status": "error"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await redis_client.aclose()
    await database_engine.dispose()


app = FastAPI(lifespan=lifespan)


@app.get("/health")
async def health_check():
    database, cache = await asyncio.gather(
        check_database(),
        check_cache(),
    )

    dependencies = {
        "database": database,
        "cache": cache,
    }

    is_healthy = all(
        dependency["status"] == "ok"
        for dependency in dependencies.values()
    )

    response = {
        "status": "healthy" if is_healthy else "unhealthy",
        "dependencies": dependencies,
    }

    return JSONResponse(
        status_code=200 if is_healthy else 503,
        content=response,
    )
