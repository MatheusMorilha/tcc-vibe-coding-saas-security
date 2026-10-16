from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timezone

from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import User, Company, Subscription, Coupon, CouponRedemption


app = FastAPI()


class CouponRequest(BaseModel):
    code: str = Field(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[A-Za-z0-9_-]+$"
    )


class CouponResponse(BaseModel):
    original_monthly_price: Decimal
    discount_amount: Decimal
    updated_monthly_price: Decimal
    currency: str


@app.post(
    "/api/v1/billing/coupons/redeem",
    response_model=CouponResponse,
)
def redeem_coupon(
    payload: CouponRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Resgata um cupom para a empresa do usuário autenticado.

    Regras importantes:
    - O tenant nunca é recebido do cliente.
    - O cupom precisa estar ativo e dentro da validade.
    - O cupom é aplicado atomicamente.
    - Um mesmo cupom não pode ser resgatado duas vezes pela mesma empresa.
    """

    # 1. Descobre o tenant exclusivamente a partir da identidade autenticada.
    company = db.scalar(
        select(Company)
        .where(
            Company.id == current_user.company_id,
            Company.is_active.is_(True),
        )
    )

    if company is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Empresa não encontrada ou inativa.",
        )

    # 2. Normaliza o código antes da consulta.
    code = payload.code.strip().upper()

    # 3. Recupera a assinatura pertencente ao tenant.
    subscription = db.scalar(
        select(Subscription)
        .where(
            Subscription.company_id == company.id,
            Subscription.status == "active",
        )
        .with_for_update()
    )

    if subscription is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A empresa não possui uma assinatura ativa.",
        )

    # 4. Recupera somente cupons válidos.
    now = datetime.now(timezone.utc)

    coupon = db.scalar(
        select(Coupon)
        .where(
            Coupon.code == code,
            Coupon.is_active.is_(True),
            Coupon.valid_from <= now,
            Coupon.valid_until >= now,
        )
        .with_for_update()
    )

    # Não revelar se o código existe mas está expirado/inativo.
    if coupon is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cupom inválido ou indisponível.",
        )

    # 5. Verifica se a empresa já utilizou esse cupom.
    already_redeemed = db.scalar(
        select(CouponRedemption.id)
        .where(
            CouponRedemption.company_id == company.id,
            CouponRedemption.coupon_id == coupon.id,
        )
        .limit(1)
    )

    if already_redeemed is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cupom já utilizado por esta empresa.",
        )

    # 6. Valida eventual limite global do cupom.
    if (
        coupon.max_redemptions is not None
        and coupon.redemption_count >= coupon.max_redemptions
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cupom esgotado.",
        )

    # 7. Calcula o desconto usando Decimal, nunca float.
    original_price = Decimal(subscription.monthly_price)

    if coupon.discount_type == "percentage":
        discount = (
            original_price * Decimal(coupon.discount_value) / Decimal("100")
        )
    elif coupon.discount_type == "fixed":
        discount = Decimal(coupon.discount_value)
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Configuração de desconto inválida.",
        )

    # Nunca permitir mensalidade negativa.
    discount = min(discount, original_price)

    updated_price = (
        original_price - discount
    ).quantize(
        Decimal("0.01"),
        rounding=ROUND_HALF_UP,
    )

    discount = (
        original_price - updated_price
    ).quantize(
        Decimal("0.01"),
        rounding=ROUND_HALF_UP,
    )

    # 8. Registra o resgate e atualiza o contador na mesma transação.
    redemption = CouponRedemption(
        company_id=company.id,
        coupon_id=coupon.id,
        user_id=current_user.id,
        redeemed_at=now,
        original_monthly_price=original_price,
        discount_amount=discount,
        final_monthly_price=updated_price,
    )

    db.add(redemption)

    coupon.redemption_count += 1

    # 9. Persiste tudo atomicamente.
    try:
        db.commit()
    except Exception:
        db.rollback()

        # Idealmente tratar aqui especificamente IntegrityError,
        # retornando conflito quando duas requisições tentarem
        # resgatar o mesmo cupom simultaneamente.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Não foi possível concluir o resgate do cupom.",
        )

    return CouponResponse(
        original_monthly_price=original_price,
        discount_amount=discount,
        updated_monthly_price=updated_price,
        currency=subscription.currency,
    )
