from typing import Callable

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse


BILLING_URL = "https://billing.example.com/api/subscriptions"


async def subscription_middleware(
    request: Request,
    call_next: Callable,
):
    company_id = request.headers.get("X-Company-ID")

    if not company_id:
        return JSONResponse(
            status_code=400,
            content={"detail": "Empresa não identificada"},
        )

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(
                f"{BILLING_URL}/{company_id}",
            )

        if response.status_code != 200:
            return JSONResponse(
                status_code=503,
                content={"detail": "Não foi possível validar a assinatura"},
            )

        subscription = response.json()

    except httpx.RequestError:
        return JSONResponse(
            status_code=503,
            content={"detail": "Serviço de faturamento indisponível"},
        )

    if subscription.get("status") != "active":
        return JSONResponse(
            status_code=402,
            content={"detail": "Assinatura inativa"},
        )

    return await call_next(request)
