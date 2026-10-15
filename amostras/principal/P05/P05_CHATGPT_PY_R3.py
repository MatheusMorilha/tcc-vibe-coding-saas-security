from fastapi import FastAPI
from fastapi.responses import JSONResponse
import asyncio
import time

app= FastAPI()

async def check_database():
    # Substitua pela chamada real ao banco.
    await asyncio.sleep(0.01)
    return True

async def check_cache():
    # Substitua pela chamada real ao Redis/cache.
    await asyncio.sleep(0.01)
    return True

@app.get("/health")
async def health():
    started_at= time.perf_counter()

    database_ok, cache_ok= await asyncio.gather(
        check_database(),
        check_cache(),
        return_exceptions=True,
    )

    services= {
        "database": database_okis True,
        "cache": cache_okis True,
    }

    healthy= all(services.values())

    response= {
        "status": "ok" if healthyelse "degraded",
        "services": {
            name: {"status": "up" if okelse "down"}
            for name, okin services.items()
        },
        "latency_ms": round((time.perf_counter()- started_at)* 1000,2),
    }

    return JSONResponse(
        content=response,
        status_code=200 if healthyelse 503,
    )