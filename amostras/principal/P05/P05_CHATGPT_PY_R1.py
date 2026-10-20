
import os
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from redis import Redis
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from redis.exceptions import RedisError

app = FastAPI(title="SaaS Health Check")

# Configurações fornecidas por variáveis de ambiente.
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ["REDIS_URL"]

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_timeout=3,
)

redis_client = Redis.from_url(
    REDIS_URL,
    socket_connect_timeout=2,
    socket_timeout=2,
    decode_responses=True,
)


def check_database() -> str:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return "healthy"
    except SQLAlchemyError:
        return "unhealthy"
    except Exception:
        return "unhealthy"


def check_cache() -> str:
    try:
        return "healthy" if redis_client.ping() else "unhealthy"
    except (RedisError, OSError, Exception):
        return "unhealthy"


@app.get("/health", tags=["Operations"])
def health_check():
    services = {
        "database": check_database(),
        "cache": check_cache(),
    }

    is_healthy = all(
        status == "healthy"
        for status in services.values()
    )

    response = {
        "status": "healthy" if is_healthy else "unhealthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": services,
    }

    return JSONResponse(
        status_code=200 if is_healthy else 503,
        content=response,
    )
