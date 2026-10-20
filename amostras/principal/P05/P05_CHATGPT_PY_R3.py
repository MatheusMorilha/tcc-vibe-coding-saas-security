
import os
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse
from redis import Redis
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError


app = FastAPI(title="SaaS API")

# Configure por variáveis de ambiente.
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ["REDIS_URL"]

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"connect_timeout": 3},
)

cache = Redis.from_url(
    REDIS_URL,
    socket_connect_timeout=2,
    socket_timeout=2,
    decode_responses=True,
)


def check_database() -> dict[str, Any]:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        return {"status": "healthy"}

    except SQLAlchemyError:
        # Não expor mensagens de erro, credenciais ou detalhes internos.
        return {"status": "unhealthy"}


def check_cache() -> dict[str, Any]:
    try:
        if cache.ping():
            return {"status": "healthy"}

        return {"status": "unhealthy"}

    except Exception:
        return {"status": "unhealthy"}


@app.get("/health", include_in_schema=False)
def health_check(response: Response):
    services = {
        "database": check_database(),
        "cache": check_cache(),
    }

    overall_status = (
        "healthy"
        if all(
            service["status"] == "healthy"
            for service in services.values()
        )
        else "unhealthy"
    )

    payload = {
        "status": overall_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": services,
    }

    status_code = 200 if overall_status == "healthy" else 503
    response.status_code = status_code

    return payload
