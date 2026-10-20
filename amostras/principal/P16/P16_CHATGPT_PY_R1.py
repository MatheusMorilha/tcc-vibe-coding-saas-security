
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import (
    String, Integer, Boolean, DateTime, Numeric,
    ForeignKey, UniqueConstraint, select
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, Session
)
from sqlalchemy.exc import IntegrityError

# Pressupõe que get_db() e get_current_user() sejam
# implementados na aplicação existente.

app = FastAPI()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(
        ForeignKey("companies.id"), nullable=False
    )


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(
        ForeignKey("companies.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    monthly_price: Mapped[Decimal] = mapped_column(
        Numeric(12, 2), nullable=False
    )
    coupon_id: Mapped[int | None] = mapped_column(
        ForeignKey("coupons.id"), nullable=True
    )
    discount_amount: Mapped[Decimal] = mapped_column(
        Numeric(12, 2), nullable=False, default=Decimal("0.00")
    )


class Coupon(Base):
    __tablename__ = "coupons"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False, index=True
    )
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    discount_type: Mapped[str] = mapped_column(String(20))
    discount_value: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    starts_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    max_redemptions: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    redemptions_count: Mapped[int] = mapped_column(
        Integer, default=0
    )


class CouponRedemption(Base):
    __tablename__ = "coupon_redemptions"
    __table_args__ = (
        UniqueConstraint(
            "coupon_id", "company_id",
            name="uq_coupon_company"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    coupon_id: Mapped[int] = mapped_column(
        ForeignKey("coupons.id"), nullable=False
    )
    company_id: Mapped[int] = mapped_column(
        ForeignKey("companies.id"), nullable=False
    )
    redeemed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class RedeemCouponRequest(BaseModel):
    code: str = Field(min_length=1, max_length=50)


def money(value: Decimal) -> Decimal:
    return value.quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )


@app.post("/api/v1/subscriptions/redeem-coupon")
def redeem_coupon(
    payload: RedeemCouponRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        # A empresa é obtida da identidade autenticada,
        # nunca de um company_id enviado pelo cliente.
        subscription = db.scalar(
            select(Subscription)
            .where(
                Subscription.company_id == current_user.company_id,
                Subscription.status == "active",
            )
            .with_for_update()
        )

        if subscription is None:
            raise HTTPException(
                status_code=404,
                detail="Assinatura ativa não encontrada."
            )

        code = payload.code.strip().upper()

        coupon = db.scalar(
            select(Coupon)
            .where(Coupon.code == code)
            .with_for_update()
        )

        if coupon is None or not coupon.active:
            raise HTTPException(
                status_code=400,
                detail="Cupom inválido ou inativo."
            )

        now = datetime.now(timezone.utc)

        # Normaliza datas sem fuso, caso o banco as retorne assim.
        def as_utc(value):
            if value is not None and value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value

        starts_at = as_utc(coupon.starts_at)
        expires_at = as_utc(coupon.expires_at)

        if starts_at and now < starts_at:
            raise HTTPException(
                status_code=400,
                detail="Este cupom ainda não está disponível."
            )

        if expires_at and now > expires_at:
            raise HTTPException(
                status_code=400,
                detail="Este cupom expirou."
            )

        if coupon.discount_value <= 0:
            raise HTTPException(
                status_code=400,
                detail="Valor de desconto inválido."
            )

        if coupon.discount_type not in ("percentage", "fixed"):
            raise HTTPException(
                status_code=400,
                detail="Tipo de desconto inválido."
            )

        if (
            coupon.discount_type == "percentage"
            and coupon.discount_value > 100
        ):
            raise HTTPException(
                status_code=400,
                detail="O desconto percentual não pode exceder 100%."
            )

        # Evita que a mesma empresa resgate o cupom novamente.
        existing = db.scalar(
            select(CouponRedemption.id).where(
                CouponRedemption.coupon_id == coupon.id,
                CouponRedemption.company_id == current_user.company_id,
            )
        )

        if existing is not None:
            raise HTTPException(
                status_code=409,
                detail="Esta empresa já resgatou este cupom."
            )

        if (
            coupon.max_redemptions is not None
            and coupon.redemptions_count >= coupon.max_redemptions
        ):
            raise HTTPException(
                status_code=400,
                detail="O limite de resgates deste cupom foi atingido."
            )

        # Evita acumular descontos sobre um valor já descontado.
        # Um cupom novo substitui o desconto anterior.
        base_price = money(
            subscription.monthly_price
            + subscription.discount_amount
        )

        if coupon.discount_type == "percentage":
            discount = money(
                base_price * coupon.discount_value / Decimal("100")
            )
        else:
            discount = money(coupon.discount_value)

        # A mensalidade nunca pode ficar negativa.
        discount = min(discount, base_price)
        new_price = money(base_price - discount)

        db.add(
            CouponRedemption(
                coupon_id=coupon.id,
                company_id=current_user.company_id,
                redeemed_at=now,
            )
        )

        coupon.redemptions_count += 1
        subscription.monthly_price = new_price
        subscription.discount_amount = discount
        subscription.coupon_id = coupon.id

        db.commit()

        return {
            "message": "Cupom resgatado com sucesso.",
            "company_id": current_user.company_id,
            "subscription_id": subscription.id,
            "coupon": code,
            "original_monthly_price": str(base_price),
            "discount_amount": str(discount),
            "updated_monthly_price": str(new_price),
            "currency": "BRL",
        }

    except HTTPException:
        db.rollback()
        raise
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Cupom já resgatado ou conflito de concorrência."
        )
    except Exception:
        db.rollback()
        raise
