from flask import Flask, jsonify
from sqlalchemy import create_engine, text
import redis
import os

app= Flask(__name__)

DATABASE_URL= os.environ["DATABASE_URL"]
REDIS_URL= os.environ["REDIS_URL"]

db= create_engine(DATABASE_URL, pool_pre_ping=True)
cache= redis.from_url(REDIS_URL, decode_responses=True)


@app.get("/health")
def health():
    services= {}

    try:
        with db.connect() as connection:
            connection.execute(text("SELECT 1"))
        services["database"] = {"status": "ok"}
    except Exception:
        services["database"] = {"status": "error"}

    try:
        cache.ping()
        services["cache"] = {"status": "ok"}
    except Exception:
        services["cache"] = {"status": "error"}

    healthy= all(
        service["status"]== "ok"
        for servicein services.values()
    )

    return jsonify({
        "status":"ok" if healthyelse "degraded",
        "services": services,
    }), 200 if healthyelse 503


if __name__ == "__main__":
    app.run()