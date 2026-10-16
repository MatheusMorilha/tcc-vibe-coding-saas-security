from decimal import Decimal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import CurrentUser, get_current_user
from app.database import get_db
from app.models import Company, Coupon, Subscription


router = APIRouter(prefix="/api/v1", tags=["coupons"])


class RedeemCouponRequest(BaseModel):
    code: str = Field(min_length=1, max_length=64)

    @field_validator("code")
    @classmethod
    def normalize_code(cls, value: str) -> str:
        # Normalização determinística sem aceitar caracteres de controle.
        value = value.strip().upper()

        if not value or any(ord(c) < 32 for c in value):
            raise ValueError("invalid coupon code")

        return value


class RedeemCouponResponse(BaseModel):
    coupon_applied: bool
    monthly_price_before: Decimal
    discount: Decimal
    monthly_price_after: Decimal


@router.post(
    "/companies/me/coupons/redeem",
    response_model=RedeemCouponResponse,
    status_code=status.HTTP_200_OK,
)
def redeem_coupon(
    payload: RedeemCouponRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RedeemCouponResponse:

    # O tenant é obtido da identidade autenticada, e NÃO de um
    # company_id fornecido pelo cliente.
    company = db.execute(
        select(Company)
        .where(
            Company.id == current_user.company_id,
            Company.is_active.is_(True),
        )
        .with_for_update()
    ).scalar_one_or_none()

    if company is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Company not found",
        )

    # Autorização: somente usuários autorizados podem alterar a assinatura.
    if not current_user.can_manage_billing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )

    subscription = db.execute(
        select(Subscription)
        .where(
            Subscription.company_id == company.id,
            Subscription.status == "active",
        )
        .with_for_update()
    ).scalar_one_or_none()

    if subscription is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No active subscription",
        )

    coupon = db.execute(
        select(Coupon)
        .where(
            Coupon.code == payload.code,
            Coupon.is_active.is_(True),
        )
        .with_for_update()
    ).scalar_one_or_none()

    # Evita revelar informações diferentes para códigos inexistentes
    # ou inválidos.
    if coupon is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Coupon cannot be redeemed",
        )

    # Validações de negócio devem ser feitas no servidor.
    if coupon.expires_at is not None and coupon.expires_at < db.execute(
        select(func.now())
    ).scalar_one():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Coupon cannot be redeemed",
        )

    if coupon.max_redemptions is not None:
        if coupon.redemption_count >= coupon.max_redemptions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Coupon cannot be redeemed",
            )

    # Evita reutilização do mesmo cupom pelo mesmo tenant.
    already_redeemed = db.execute(
        select(CouponRedemption.id)
        .where(
            CouponRedemption.coupon_id == coupon.id,
            CouponRedemption.company_id == company.id,
        )
    ).scalar_one_or_none()

    if already_redeemed is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Coupon already redeemed",
        )

    original_price = subscription.monthly_price

    if coupon.discount_type == "percentage":
        discount = (
            original_price * coupon.discount_value / Decimal("100")
        )
    elif coupon.discount_type == "fixed":
        discount = coupon.discount_value
    else:
        # Estado inválido de dados internos: não expor detalhes.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to redeem coupon",
        )

    # Nunca permitir mensalidade negativa.
    discount = min(discount, original_price)
    updated_price = original_price - discount

    redemption = CouponRedemption(
        coupon_id=coupon.id,
        company_id=company.id,
        subscription_id=subscription.id,
    )

    subscription.monthly_price = updated_price
    coupon.redemption_count += 1

    db.add(redemption)

    try:
        # Commit atômico: atualização da assinatura e resgate do cupom
        # precisam ocorrer juntos.
        db.commit()
    except IntegrityError:
        db.rollback()

        # Uma constraint UNIQUE em
        # (coupon_id, company_id) protege contra concorrência.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Coupon already redeemed",
        )

    return RedeemCouponResponse(
        coupon_applied=True,
        monthly_price_before=original_price,
        discount=discount,
        monthly_price_after=updated_price,
    )
