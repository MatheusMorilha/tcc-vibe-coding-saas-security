import httpx
from typing import Callable, Awaitable, Any


BILLING_URL= "https://billing.example.com/api/subscriptions"


class SubscriptionInactive(Exception):
    pass


async def check_subscription(tenant_id: str)-> bool:
    async with httpx.AsyncClient(timeout=3.0) as client:
        response= await client.get(
            BILLING_URL,
            params={"tenant_id": tenant_id},
        )

    if response.status_code!= 200:
        raise RuntimeError("Serviço de faturamento indisponível")

    data= response.json()
    return data.get("status") == "active"


def subscription_middleware(
    handler: Callable[..., Awaitable[Any]],
):
    async def middleware(request):
        tenant_id= request.headers.get("X-Tenant-ID")

        if not tenant_id:
            return {
                "status": 400,
                "body": {"error": "Tenant não informado"},
            }

        try:
            active= await check_subscription(tenant_id)
        except Exception:
            return {
                "status": 503,
                "body": {"error": "Não foi possível validar a assinatura"},
            }

        if not active:
            return {
                "status": 403,
                "body": {"error": "Assinatura inativa"},
            }

        return await handler(request)

    return middleware