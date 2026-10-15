from decimal import Decimal
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

app= FastAPI()


class CouponRequest(BaseModel):
    code: str


class Coupon(Base):
    __tablename__= "coupons"

    id = Column(Integer, primary_key=True)
    code= Column(String, unique=True, nullable=False)
    discount_percent= Column(Numeric(5,2), nullable=False)
    active= Column(Boolean, default=True)


class Subscription(Base):
    __tablename__= "subscriptions"

    id = Column(Integer, primary_key=True)
    tenant_id= Column(Integer, nullable=False, index=True)
    monthly_price= Column(Numeric(10,2), nullable=False)
    coupon_id= Column(Integer, nullable=True)


def get_current_tenant_id():
    # Obtido do usuário autenticado/token JWT.
    return 123


def get_db():
    # Retorna uma sessão SQLAlchemy.
    ...


@app.post("/api/v1/subscription/coupon")
def redeem_coupon(
    request: CouponRequest,
    db: Session= Depends(get_db),
):
    tenant_id= get_current_tenant_id()

    coupon= db.scalar(
        select(Coupon).where(
            Coupon.code== request.code,
            Coupon.active.is_(True),
        )
    )

    if not coupon:
        raise HTTPException(
            status_code=404,
            detail="Cupom inválido ou inativo",
        )

    # O tenant_id vem da autenticação, nunca do payload.
    subscription= db.scalar(
        select(Subscription)
        .where(Subscription.tenant_id== tenant_id)
        .with_for_update()
    )

    if not subscription:
        raise HTTPException(
            status_code=404,
            detail="Assinatura não encontrada",
        )

    if subscription.coupon_idis not None:
        raise HTTPException(
            status_code=409,
            detail="A assinatura já possui um cupom aplicado",
        )

    original_price= Decimal(subscription.monthly_price)
    discount= (
        original_price* Decimal(coupon.discount_percent) / Decimal("100")
    )

    updated_price= max(
        Decimal("0.00"),
        original_price- discount,
    ).quantize(Decimal("0.01"))

    subscription.coupon_id= coupon.id
    subscription.monthly_price= updated_price

    db.commit()
    db.refresh(subscription)

    return {
        "tenant_id": tenant_id,
        "coupon": coupon.code,
        "discount_percent": float(coupon.discount_percent),
        "original_monthly_price": float(original_price),
        "updated_monthly_price": float(updated_price),
    }