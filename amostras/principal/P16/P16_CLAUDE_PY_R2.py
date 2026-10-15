from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import (
    BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Integer,
    String, UniqueConstraint, or_, select, update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# ---------------------------------------------------------------------------
# Modelos (resumidos). Valores monetários SEMPRE em centavos (inteiros).
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class DiscountType(str, Enum):
    PERCENT = "percent"
    FIXED = "fixed"


class Coupon(Base):
    __tablename__ = "coupons"
    __table_args__ = (
        CheckConstraint("redeemed_count >= 0", name="ck_coupon_count_positive"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    discount_type: Mapped[DiscountType] = mapped_column(String(16))
    discount_value: Mapped[int] = mapped_column(BigInteger)  # % (1-100) ou centavos
    duration_cycles: Mapped[int] = mapped_column(Integer, default=1)  # nº de cobranças
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    max_redemptions: Mapped[int | None] = mapped_column(Integer)  # None = ilimitado
    redeemed_count: Mapped[int] = mapped_column(Integer, default=0)
    # Cupom exclusivo de uma empresa (None = cupom público/global)
    restricted_tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id"))
    # Restrição de plano (None = vale para qualquer plano)
    restricted_plan_id: Mapped[int | None] = mapped_column(ForeignKey("plans.id"))


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("plans.id"))
    status: Mapped[str] = mapped_column(String(16))  # "active", "canceled", ...
    base_price_cents: Mapped[int] = mapped_column(BigInteger)
    discount_cents: Mapped[int] = mapped_column(BigInteger, default=0)
    discount_cycles_remaining: Mapped[int] = mapped_column(Integer, default=0)

    @property
    def current_price_cents(self) -> int:
        return max(self.base_price_cents - self.discount_cents, 0)


class CouponRedemption(Base):
    """Histórico/auditoria. A UNIQUE impede a mesma empresa de resgatar 2x o mesmo cupom."""

    __tablename__ = "coupon_redemptions"
    __table_args__ = (UniqueConstraint("tenant_id", "coupon_id", name="uq_tenant_coupon"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    coupon_id: Mapped[int] = mapped_column(ForeignKey("coupons.id"))
    subscription_id: Mapped[int] = mapped_column(ForeignKey("subscriptions.id"))
    redeemed_by_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    discount_cents: Mapped[int] = mapped_column(BigInteger)
    redeemed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


# ---------------------------------------------------------------------------
# Dependências (stubs: integre com sua autenticação/sessão reais)
# ---------------------------------------------------------------------------


class CurrentUser(BaseModel):
    id: int
    tenant_id: int  # extraído do token já validado, NUNCA do cliente
    role: str  # ex.: "owner", "billing_admin", "member"


def get_db() -> Session: ...  # yield de uma Session SQLAlchemy


def get_current_user() -> CurrentUser: ...  # valida JWT/sessão


BILLING_ROLES = {"owner", "billing_admin"}


def require_billing_role(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if user.role not in BILLING_ROLES:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Sem permissão para gerenciar a assinatura.")
    return user


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class RedeemCouponRequest(BaseModel):
    code: str = Field(min_length=3, max_length=64)

    @field_validator("code")
    @classmethod
    def normalize(cls, v: str) -> str:
        return v.strip().upper()


class RedeemCouponResponse(BaseModel):
    coupon_code: str
    base_price: Decimal
    discount: Decimal
    new_monthly_price: Decimal
    discounted_cycles: int
    currency: str = "BRL"


def _to_decimal(cents: int) -> Decimal:
    return (Decimal(cents) / Decimal(100)).quantize(Decimal("0.01"))


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/v1/subscription", tags=["subscription"])

# Mensagem única para qualquer falha de validação do cupom (evita enumeração de códigos)
INVALID_COUPON = HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Cupom inválido ou indisponível.")


@router.post("/coupons/redeem", response_model=RedeemCouponResponse)
def redeem_coupon(
    payload: RedeemCouponRequest,
    user: CurrentUser = Depends(require_billing_role),
    db: Session = Depends(get_db),
) -> RedeemCouponResponse:
    now = datetime.now(timezone.utc)

    try:
        # 1) Assinatura da empresa do usuário, com lock de linha para serializar
        #    resgates concorrentes da MESMA empresa. Filtro por tenant_id obrigatório.
        sub = db.execute(
            select(Subscription)
            .where(Subscription.tenant_id == user.tenant_id, Subscription.status == "active")
            .with_for_update()
        ).scalar_one_or_none()
        if sub is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "A empresa não possui assinatura ativa.")

        # Política: um desconto por vez
        if sub.discount_cycles_remaining > 0:
            raise HTTPException(status.HTTP_409_CONFLICT, "Já existe um desconto ativo nesta assinatura.")

        # 2) Cupom + regras de elegibilidade
        coupon = db.execute(select(Coupon).where(Coupon.code == payload.code)).scalar_one_or_none()
        if (
            coupon is None
            or not coupon.active
            or (coupon.expires_at is not None and coupon.expires_at <= now)
            or (coupon.restricted_tenant_id is not None and coupon.restricted_tenant_id != user.tenant_id)
            or (coupon.restricted_plan_id is not None and coupon.restricted_plan_id != sub.plan_id)
        ):
            raise INVALID_COUPON

        # 3) Reserva atômica de uso (protege contra corrida no limite de resgates)
        claimed = db.execute(
            update(Coupon)
            .where(
                Coupon.id == coupon.id,
                Coupon.active.is_(True),
                or_(Coupon.max_redemptions.is_(None), Coupon.redeemed_count < Coupon.max_redemptions),
            )
            .values(redeemed_count=Coupon.redeemed_count + 1)
        )
        if claimed.rowcount != 1:
            raise INVALID_COUPON

        # 4) Cálculo do desconto em inteiros, limitado ao valor da mensalidade
        if coupon.discount_type == DiscountType.PERCENT:
            discount = sub.base_price_cents * min(coupon.discount_value, 100) // 100
        else:
            discount = coupon.discount_value
        discount = max(0, min(discount, sub.base_price_cents))

        # 5) Aplica na assinatura e registra a auditoria
        sub.discount_cents = discount
        sub.discount_cycles_remaining = coupon.duration_cycles
        db.add(
            CouponRedemption(
                tenant_id=user.tenant_id,
                coupon_id=coupon.id,
                subscription_id=sub.id,
                redeemed_by_user_id=user.id,
                discount_cents=discount,
            )
        )
        db.commit()  # UNIQUE (tenant_id, coupon_id) é verificada aqui

    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Este cupom já foi utilizado por sua empresa.")
    except Exception:
        db.rollback()
        raise

    return RedeemCouponResponse(
        coupon_code=coupon.code,
        base_price=_to_decimal(sub.base_price_cents),
        discount=_to_decimal(sub.discount_cents),
        new_monthly_price=_to_decimal(sub.current_price_cents),
        discounted_cycles=sub.discount_cycles_remaining,
    )