"""
POST /api/v1/subscription/coupons/redeem

Resgata um cupom promocional para a assinatura da empresa do usuário autenticado
e retorna o valor atualizado da mensalidade.

Decisões de segurança e consistência:
- O tenant (company_id) vem SEMPRE do token/sessão, nunca do corpo da requisição
  (evita IDOR: uma empresa aplicando cupom na assinatura de outra).
- Somente usuários com papel de admin/financeiro da empresa podem resgatar.
- Valores monetários em centavos (int): sem erros de ponto flutuante.
- O desconto é calculado no servidor; o cliente nunca informa valores.
- Locks de linha (SELECT ... FOR UPDATE) + constraint única evitam condição de
  corrida: estouro do limite global de usos e resgate duplo pela mesma empresa.
- Mensagens de erro genéricas para cupom inexistente/inválido (evita enumeração
  de códigos).
"""

from __future__ import annotations

import enum
import logging
from datetime import datetime, timezone
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import (
    BigInteger, Boolean, DateTime, Enum, ForeignKey, Integer, String,
    UniqueConstraint, select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("billing.coupons")


# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class DiscountType(str, enum.Enum):
    PERCENT = "percent"  # discount_value = 1..100
    FIXED = "fixed"      # discount_value = centavos


class SubscriptionStatus(str, enum.Enum):
    ACTIVE = "active"
    CANCELED = "canceled"
    PAST_DUE = "past_due"


class Coupon(Base):
    __tablename__ = "coupons"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # sempre em UPPER
    discount_type: Mapped[DiscountType] = mapped_column(Enum(DiscountType))
    discount_value: Mapped[int] = mapped_column(BigInteger)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    max_redemptions: Mapped[int | None] = mapped_column(Integer, nullable=True)  # None = ilimitado
    redemptions_count: Mapped[int] = mapped_column(Integer, default=0)
    plan_id: Mapped[int | None] = mapped_column(ForeignKey("plans.id"), nullable=True)  # None = qualquer plano


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), unique=True, index=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("plans.id"))
    status: Mapped[SubscriptionStatus] = mapped_column(Enum(SubscriptionStatus))
    base_price_cents: Mapped[int] = mapped_column(BigInteger)       # preço de tabela do plano
    discount_cents: Mapped[int] = mapped_column(BigInteger, default=0)
    current_price_cents: Mapped[int] = mapped_column(BigInteger)    # base - desconto
    coupon_id: Mapped[int | None] = mapped_column(ForeignKey("coupons.id"), nullable=True)


class CouponRedemption(Base):
    __tablename__ = "coupon_redemptions"
    __table_args__ = (
        # Garante, no nível do banco, que uma empresa resgata o mesmo cupom só uma vez.
        UniqueConstraint("coupon_id", "company_id", name="uq_redemption_coupon_company"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    coupon_id: Mapped[int] = mapped_column(ForeignKey("coupons.id"))
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    subscription_id: Mapped[int] = mapped_column(ForeignKey("subscriptions.id"))
    redeemed_by_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    discount_cents: Mapped[int] = mapped_column(BigInteger)
    redeemed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class RedeemCouponRequest(BaseModel):
    code: str = Field(..., min_length=3, max_length=64)

    @field_validator("code")
    @classmethod
    def normalize_code(cls, v: str) -> str:
        v = v.strip().upper()
        if not v.replace("-", "").replace("_", "").isalnum():
            raise ValueError("Formato de cupom inválido.")
        return v


class RedeemCouponResponse(BaseModel):
    coupon_code: str
    previous_monthly_price: Decimal
    discount_amount: Decimal
    new_monthly_price: Decimal
    currency: str = "BRL"


# --------------------------------------------------------------------------- #
# Dependências (a serem ligadas à infraestrutura real da aplicação)
# --------------------------------------------------------------------------- #
class CurrentUser(BaseModel):
    id: int
    company_id: int
    role: str  # ex.: "owner", "admin", "finance", "member"


def get_db() -> Session:  # pragma: no cover - fornecido pela aplicação
    raise NotImplementedError


def get_current_user() -> CurrentUser:  # pragma: no cover - fornecido pela aplicação
    """Deve validar o token e devolver o usuário com o company_id do TOKEN."""
    raise NotImplementedError


BILLING_ROLES = {"owner", "admin", "finance"}


def require_billing_permission(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if user.role not in BILLING_ROLES:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Sem permissão para gerenciar a assinatura.")
    return user


# --------------------------------------------------------------------------- #
# Regras de negócio
# --------------------------------------------------------------------------- #
INVALID_COUPON_MSG = "Cupom inválido ou indisponível."


def compute_discount_cents(coupon: Coupon, base_price_cents: int) -> int:
    if coupon.discount_type == DiscountType.PERCENT:
        pct = max(0, min(coupon.discount_value, 100))
        discount = (base_price_cents * pct) // 100
    else:
        discount = max(0, coupon.discount_value)
    # O desconto nunca pode ultrapassar o preço (mensalidade não fica negativa).
    return min(discount, base_price_cents)


def cents_to_decimal(cents: int) -> Decimal:
    return (Decimal(cents) / Decimal(100)).quantize(Decimal("0.01"))


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #
router = APIRouter(prefix="/api/v1/subscription", tags=["subscription"])


@router.post(
    "/coupons/redeem",
    response_model=RedeemCouponResponse,
    status_code=status.HTTP_200_OK,
)
def redeem_coupon(
    payload: RedeemCouponRequest,
    user: CurrentUser = Depends(require_billing_permission),
    db: Session = Depends(get_db),
) -> RedeemCouponResponse:
    now = datetime.now(timezone.utc)

    try:
        # 1) Assinatura da empresa do usuário, com lock da linha. Serializa
        #    resgates concorrentes da mesma empresa. O filtro por company_id
        #    garante o isolamento entre tenants.
        subscription = db.execute(
            select(Subscription)
            .where(Subscription.company_id == user.company_id)
            .with_for_update()
        ).scalar_one_or_none()

        if subscription is None or subscription.status != SubscriptionStatus.ACTIVE:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "A empresa não possui uma assinatura ativa.",
            )

        # 2) Cupom, com lock da linha para controlar o limite global de usos.
        coupon = db.execute(
            select(Coupon).where(Coupon.code == payload.code).with_for_update()
        ).scalar_one_or_none()

        # 3) Validações (mensagem genérica para não revelar o motivo exato).
        if (
            coupon is None
            or not coupon.is_active
            or (coupon.valid_from and now < coupon.valid_from)
            or (coupon.valid_until and now > coupon.valid_until)
            or (coupon.max_redemptions is not None
                and coupon.redemptions_count >= coupon.max_redemptions)
            or (coupon.plan_id is not None and coupon.plan_id != subscription.plan_id)
        ):
            logger.info(
                "coupon_redeem_rejected company_id=%s user_id=%s",
                user.company_id, user.id,
            )
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, INVALID_COUPON_MSG)

        # 4) Regras de unicidade: um cupom ativo por assinatura e uma vez por empresa.
        if subscription.coupon_id is not None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "A assinatura já possui um cupom aplicado.",
            )

        already_redeemed = db.execute(
            select(CouponRedemption.id).where(
                CouponRedemption.coupon_id == coupon.id,
                CouponRedemption.company_id == user.company_id,
            )
        ).first()
        if already_redeemed:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Este cupom já foi utilizado pela empresa.",
            )

        # 5) Cálculo do desconto sempre sobre o preço base (não acumula).
        previous_price = subscription.current_price_cents
        discount = compute_discount_cents(coupon, subscription.base_price_cents)
        new_price = subscription.base_price_cents - discount

        # 6) Persistência atômica: assinatura + contador + registro de auditoria.
        subscription.discount_cents = discount
        subscription.current_price_cents = new_price
        subscription.coupon_id = coupon.id
        coupon.redemptions_count += 1

        db.add(
            CouponRedemption(
                coupon_id=coupon.id,
                company_id=user.company_id,
                subscription_id=subscription.id,
                redeemed_by_user_id=user.id,
                discount_cents=discount,
                redeemed_at=now,
            )
        )
        db.commit()

    except IntegrityError:
        # Última linha de defesa: a constraint única barrou um resgate duplicado.
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Este cupom já foi utilizado pela empresa.")
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        logger.exception("coupon_redeem_error company_id=%s", user.company_id)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Não foi possível resgatar o cupom. Tente novamente.",
        )

    logger.info(
        "coupon_redeemed company_id=%s user_id=%s coupon_id=%s discount_cents=%s",
        user.company_id, user.id, coupon.id, discount,
    )

    return RedeemCouponResponse(
        coupon_code=coupon.code,
        previous_monthly_price=cents_to_decimal(previous_price),
        discount_amount=cents_to_decimal(discount),
        new_monthly_price=cents_to_decimal(new_price),
    )