"""
Resgate de cupom promocional em plataforma SaaS multilocatária.

Decisões de segurança importantes:
  1. O tenant (company_id) vem SEMPRE do usuário autenticado, nunca do corpo/URL.
  2. Apenas perfis com permissão de cobrança podem resgatar cupons.
  3. A assinatura é lida com lock de linha (SELECT ... FOR UPDATE) dentro da transação.
  4. O limite global de usos é verificado de forma atômica (UPDATE condicional),
     evitando que requisições simultâneas ultrapassem o máximo de resgates.
  5. Constraint UNIQUE (company_id, coupon_id) impede resgate duplicado mesmo sob corrida.
  6. Cálculo monetário com Decimal (nunca float).
  7. Erros de cupom inexistente/expirado/inativo retornam a MESMA mensagem
     genérica, dificultando enumeração de códigos válidos.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import (
    CheckConstraint, DateTime, Enum, ForeignKey, Integer, Numeric, String,
    UniqueConstraint, select, update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# --------------------------------------------------------------------------
# Modelos
# --------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class DiscountType(str, enum.Enum):
    PERCENT = "percent"
    FIXED = "fixed"


class Coupon(Base):
    __tablename__ = "coupons"
    __table_args__ = (
        CheckConstraint("discount_value > 0", name="ck_coupon_value_positive"),
        CheckConstraint(
            "discount_type <> 'percent' OR discount_value <= 100",
            name="ck_coupon_percent_max",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # sempre MAIÚSCULO
    discount_type: Mapped[DiscountType] = mapped_column(Enum(DiscountType))
    discount_value: Mapped[Decimal] = mapped_column(Numeric(10, 2))
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    max_redemptions: Mapped[int | None] = mapped_column(Integer, nullable=True)
    redemptions_count: Mapped[int] = mapped_column(Integer, default=0)
    active: Mapped[bool] = mapped_column(default=True)
    # Restringe o cupom a um plano específico (None = qualquer plano)
    plan_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    company_id: Mapped[uuid.UUID] = mapped_column(index=True)
    plan_id: Mapped[uuid.UUID]
    status: Mapped[str] = mapped_column(String(20))  # "active", "canceled", ...
    base_price: Mapped[Decimal] = mapped_column(Numeric(10, 2))  # preço de tabela
    discount_amount: Mapped[Decimal] = mapped_column(Numeric(10, 2), default=Decimal("0.00"))
    coupon_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("coupons.id"), nullable=True
    )


class CouponRedemption(Base):
    __tablename__ = "coupon_redemptions"
    __table_args__ = (
        # Cada empresa só pode resgatar um mesmo cupom uma vez
        UniqueConstraint("company_id", "coupon_id", name="uq_redemption_company_coupon"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    company_id: Mapped[uuid.UUID] = mapped_column(index=True)
    coupon_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("coupons.id"))
    subscription_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("subscriptions.id"))
    redeemed_by_user_id: Mapped[uuid.UUID]
    redeemed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# --------------------------------------------------------------------------
# Dependências (substitua pelas implementações reais do projeto)
# --------------------------------------------------------------------------


class CurrentUser(BaseModel):
    id: uuid.UUID
    company_id: uuid.UUID  # extraído do token JWT/sessão, NUNCA do cliente
    role: str


def get_db() -> Session:  # pragma: no cover - fornecido pela aplicação
    raise NotImplementedError


def get_current_user() -> CurrentUser:  # pragma: no cover - fornecido pela aplicação
    raise NotImplementedError


BILLING_ROLES = {"owner", "admin", "billing"}


def require_billing_permission(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if user.role not in BILLING_ROLES:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Sem permissão para gerenciar a assinatura.")
    return user


# Recomenda-se aplicar rate limit nesta rota (ex.: slowapi / gateway), por usuário
# e por empresa, para impedir tentativa de adivinhação de códigos (brute force).

# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------


class RedeemCouponRequest(BaseModel):
    code: str = Field(min_length=3, max_length=64)

    @field_validator("code")
    @classmethod
    def normalize(cls, v: str) -> str:
        v = v.strip().upper()
        if not v.replace("-", "").replace("_", "").isalnum():
            raise ValueError("Formato de cupom inválido.")
        return v


class RedeemCouponResponse(BaseModel):
    subscription_id: uuid.UUID
    coupon_code: str
    base_price: Decimal
    discount_amount: Decimal
    monthly_price: Decimal  # valor atualizado da mensalidade
    currency: str = "BRL"


# --------------------------------------------------------------------------
# Regras de negócio
# --------------------------------------------------------------------------

CENT = Decimal("0.01")
INVALID_COUPON = HTTPException(
    status.HTTP_404_NOT_FOUND, "Cupom inválido ou indisponível."
)


def compute_discount(coupon: Coupon, base_price: Decimal) -> Decimal:
    if coupon.discount_type is DiscountType.PERCENT:
        discount = base_price * coupon.discount_value / Decimal(100)
    else:
        discount = coupon.discount_value
    discount = discount.quantize(CENT, rounding=ROUND_HALF_UP)
    return min(discount, base_price)  # o preço final nunca fica negativo


# --------------------------------------------------------------------------
# Rota
# --------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/subscription", tags=["subscription"])


@router.post("/coupons/redeem", response_model=RedeemCouponResponse)
def redeem_coupon(
    payload: RedeemCouponRequest,
    user: CurrentUser = Depends(require_billing_permission),
    db: Session = Depends(get_db),
) -> RedeemCouponResponse:
    now = datetime.now(timezone.utc)

    try:
        # 1) Assinatura da empresa do usuário autenticado, com lock de linha.
        #    O filtro por company_id garante o isolamento entre tenants.
        subscription = db.execute(
            select(Subscription)
            .where(
                Subscription.company_id == user.company_id,
                Subscription.status == "active",
            )
            .with_for_update()
        ).scalar_one_or_none()

        if subscription is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Nenhuma assinatura ativa encontrada.")

        # 2) Cupom: validação de existência, vigência e aplicabilidade.
        coupon = db.execute(
            select(Coupon).where(Coupon.code == payload.code)
        ).scalar_one_or_none()

        if (
            coupon is None
            or not coupon.active
            or coupon.valid_from > now
            or (coupon.valid_until is not None and coupon.valid_until <= now)
            or (coupon.plan_id is not None and coupon.plan_id != subscription.plan_id)
        ):
            raise INVALID_COUPON  # mesma resposta para todos os casos

        # 3) Sem acúmulo de cupons: a assinatura só pode ter um cupom aplicado.
        if subscription.coupon_id is not None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "A assinatura já possui um cupom aplicado.",
            )

        # 4) Incremento atômico do contador, respeitando o limite global.
        result = db.execute(
            update(Coupon)
            .where(
                Coupon.id == coupon.id,
                (Coupon.max_redemptions.is_(None))
                | (Coupon.redemptions_count < Coupon.max_redemptions),
            )
            .values(redemptions_count=Coupon.redemptions_count + 1)
        )
        if result.rowcount == 0:
            raise INVALID_COUPON  # esgotado

        # 5) Registro do resgate (UNIQUE impede duplicidade por empresa).
        db.add(
            CouponRedemption(
                company_id=user.company_id,
                coupon_id=coupon.id,
                subscription_id=subscription.id,
                redeemed_by_user_id=user.id,
                redeemed_at=now,
            )
        )

        # 6) Aplica o desconto à assinatura.
        discount = compute_discount(coupon, subscription.base_price)
        subscription.discount_amount = discount
        subscription.coupon_id = coupon.id

        db.flush()  # dispara a constraint UNIQUE antes do commit
        db.commit()

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Este cupom já foi resgatado por sua empresa."
        )
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise

    return RedeemCouponResponse(
        subscription_id=subscription.id,
        coupon_code=coupon.code,
        base_price=subscription.base_price,
        discount_amount=subscription.discount_amount,
        monthly_price=subscription.base_price - subscription.discount_amount,
    )