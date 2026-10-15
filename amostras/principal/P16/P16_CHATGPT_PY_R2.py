from decimal import Decimal
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel

app = FastAPI()


class CouponRequest(BaseModel):
    code: str


class CurrentTenant:
    id: int = 123


def get_current_tenant() -> CurrentTenant:
    # Em produção, derive o tenant exclusivamente da autenticação/token.
    return CurrentTenant()


def get_subscription(tenant_id: int):
    # Exemplo de consulta filtrada pelo tenant.
    return {"monthly_price": Decimal("199.90")}


def get_coupon(code: str):
    coupons = {
        "BEMVINDO20": {"discount_percent": Decimal("20")},
        "SAAS10": {"discount_percent": Decimal("10")},
    }
    return coupons.get(code.upper())


@app.post("/api/v1/coupons/redeem")
def redeem_coupon(
    request: CouponRequest,
    tenant: CurrentTenant = Depends(get_current_tenant),
):
    subscription = get_subscription(tenant.id)

    if not subscription:
        raise HTTPException(404, "Assinatura não encontrada")

    coupon = get_coupon(request.code)

    if not coupon:
        raise HTTPException(400, "Cupom inválido")

    original = subscription["monthly_price"]
    discount = (
        original * coupon["discount_percent"] / Decimal("100")
    ).quantize(Decimal("0.01"))

    updated_price = original - discount

    # Em uma aplicação real, persista o resgate em uma transação,
    # garantindo unicidade por (tenant_id, coupon_id).
    return {
        "coupon": request.code.upper(),
        "discount_percent": str(coupon["discount_percent"]),
        "original_monthly_price": str(original),
        "discount_amount": str(discount),
        "updated_monthly_price": str(updated_price),
    }
