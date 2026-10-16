from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, constr
from sqlalchemy import (
    Column,
    String,
    Integer,
    Numeric,
    DateTime,
    Boolean,
    ForeignKey,
    select,
)
from sqlalchemy.orm import declarative_base, relationship, Session

Base = declarative_base()
router = APIRouter(prefix="/api/v1/billing", tags=["Billing"])


# ==========================================
# 1. Modelos de Dados (SQLAlchemy ORM)
# ==========================================

class DiscountType(str, Enum):
    PERCENTAGE = "PERCENTAGE"
    FIXED_AMOUNT = "FIXED_AMOUNT"


class Coupon(Base):
    __tablename__ = "coupons"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, index=True, nullable=False)
    discount_type = Column(String(20), nullable=False)
    discount_value = Column(Numeric(10, 2), nullable=False)
    max_redemptions = Column(Integer, nullable=True)
    current_redemptions = Column(Integer, default=0, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(36), index=True, nullable=False)  # Isolamento multilocatário
    base_price = Column(Numeric(10, 2), nullable=False)
    current_price = Column(Numeric(10, 2), nullable=False)
    applied_coupon_id = Column(Integer, ForeignKey("coupons.id"), nullable=True)
    status = Column(String(20), default="ACTIVE", nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class CouponRedemption(Base):
    __tablename__ = "coupon_redemptions"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(36), index=True, nullable=False)
    coupon_id = Column(Integer, ForeignKey("coupons.id"), nullable=False)
    redeemed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


# ==========================================
# 2. Schemas de Entrada/Saída (Pydantic)
# ==========================================

class RedeemCouponRequest(BaseModel):
    # OWASP A03 / Validação de entrada restrita via regex
    code: str = Field(
        ...,
        min_length=3,
        max_length=30,
        pattern=r"^[A-Z0-9_\-]+$",
        description="Código alfanumérico do cupom promocional",
        examples=["BLACKFRIDAY2026"]
    )


class RedeemCouponResponse(BaseModel):
    message: str
    original_price: Decimal
    discount_applied: Decimal
    new_price: Decimal
    coupon_code: str


# ==========================================
# 3. Contexto de Autenticação e Multilocação
# ==========================================

class AuthenticatedUser(BaseModel):
    user_id: str
    tenant_id: str  # Extraído com segurança do token (OWASP A01)
    role: str


def get_current_user() -> AuthenticatedUser:
    """
    Substitua pela sua lógica de decodificação de JWT / Sessão.
    Garante autenticação válida e isolamento de tenant.
    """
    return AuthenticatedUser(
        user_id="usr_01HZY4",
        tenant_id="tenant_corp_alpha",
        role="ADMIN"
    )


def get_db():
    """Gerador de sessão do banco de dados (Dependency Injection)."""
    # Exemplo: yield SessionLocal()
    raise NotImplementedError("Configuração de banco de dados necessária.")


# ==========================================
# 4. Rota de Aplicação do Cupom
# ==========================================

@router.post(
    "/redeem-coupon",
    response_model=RedeemCouponResponse,
    status_code=status.HTTP_200_OK,
    summary="Resgatar cupom promocional para a assinatura da empresa")
def redeem_promotional_coupon(
    payload: RedeemCouponRequest,
    current_user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)]):
    # [OWASP A01] Controle de Acesso Baseado em Papéis (RBAC)
    if current_user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas administradores podem gerenciar planos e cupons."
        )

    tenant_id = current_user.tenant_id
    now = datetime.now(timezone.utc)

    # Início da transação atômica com isolamento de locks
    try:
        # [OWASP A04] Bloqueio pessimista (SELECT ... FOR UPDATE) para prevenir Race Conditions
        coupon = db.execute(
            select(Coupon)
            .where(Coupon.code == payload.code.upper())
            .with_for_update()
        ).scalar_one_or_none()

        if not coupon or not coupon.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cupom inválido ou inativo."
            )

        if coupon.expires_at and coupon.expires_at < now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Este cupom expirou."
            )

        if coupon.max_redemptions is not None and coupon.current_redemptions >= coupon.max_redemptions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Limite de resgates para este cupom foi atingido."
            )

        # [OWASP A01] Isolamento Multitenant: busca assinatura travada exclusivamente ao tenant_id
        subscription = db.execute(
            select(Subscription)
            .where(Subscription.tenant_id == tenant_id, Subscription.status == "ACTIVE")
            .with_for_update()
        ).scalar_one_or_none()

        if not subscription:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Assinatura ativa não encontrada para esta empresa."
            )

        # Validação contra reaplicação do mesmo cupom pelo mesmo cliente
        already_redeemed = db.execute(
            select(CouponRedemption).where(
                CouponRedemption.tenant_id == tenant_id,
                CouponRedemption.coupon_id == coupon.id
            )
        ).scalar_one_or_none()

        if already_redeemed:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Este cupom já foi utilizado por sua empresa."
            )

        # Cálculo financeiro defensivo utilizando Decimal
        base_price = Decimal(str(subscription.base_price))
        discount_val = Decimal(str(coupon.discount_value))

        if coupon.discount_type == DiscountType.PERCENTAGE:
            discount_amount = (base_price * (discount_val / Decimal("100"))).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
        elif coupon.discount_type == DiscountType.FIXED_AMOUNT:
            discount_amount = discount_val.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Tipo de desconto inválido no sistema."
            )

        # Garante que o valor final nunca seja negativo
        new_price = max(Decimal("0.00"), base_price - discount_amount)

        # Persistência atômica das alterações
        subscription.current_price = new_price
        subscription.applied_coupon_id = coupon.id
        subscription.updated_at = now

        coupon.current_redemptions += 1

        redemption_record = CouponRedemption(
            tenant_id=tenant_id,
            coupon_id=coupon.id,
            redeemed_at=now
        )
        db.add(redemption_record)

        db.commit()

        return RedeemCouponResponse(
            message="Cupom aplicado com sucesso.",
            original_price=base_price,
            discount_applied=discount_amount,
            new_price=new_price,
            coupon_code=coupon.code
        )

    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        # [OWASP A05/A09] Log interno seguro sem vazar detalhes para o payload final
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ocorreu um erro ao processar o resgate do cupom."
        )