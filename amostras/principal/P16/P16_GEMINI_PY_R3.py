from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, DateTime, Numeric, Integer, ForeignKey, Boolean, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

# ==============================================================================
# MODELOS DE DADOS (DATABASE MODELS)
# ==============================================================================

class DiscountType(str, Enum):
    PERCENTAGE = "PERCENTAGE"
    FIXED_AMOUNT = "FIXED_AMOUNT"


class Coupon(Base):
    __tablename__ = "coupons"

    id = Column(String, primary_key=True)
    code = Column(String, unique=True, nullable=False, index=True)
    discount_type = Column(String, nullable=False)  # PERCENTAGE ou FIXED_AMOUNT
    discount_value = Column(Numeric(10, 2), nullable=False)
    max_uses = Column(Integer, nullable=True)
    uses_count = Column(Integer, default=0, nullable=False)
    valid_until = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(String, primary_key=True)
    company_id = Column(String, nullable=False, index=True) # Tenant ID
    base_price = Column(Numeric(10, 2), nullable=False)
    current_price = Column(Numeric(10, 2), nullable=False)
    active_coupon_id = Column(String, ForeignKey("coupons.id"), nullable=True)


class CouponRedemption(Base):
    __tablename__ = "coupon_redemptions"

    id = Column(String, primary_key=True)
    company_id = Column(String, nullable=False, index=True)
    coupon_id = Column(String, ForeignKey("coupons.id"), nullable=False)
    redeemed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# ==============================================================================
# SCHEMAS DE REQUISIÇÃO E RESPOSTA (PYDANTIC)
# ==============================================================================

class RedeemCouponRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=50, description="Código do cupom promocional")


class RedeemCouponResponse(BaseModel):
    message: str
    company_id: str
    original_price: Decimal
    discount_applied: Decimal
    updated_monthly_price: Decimal
    coupon_code: str


# Dummy do contexto do usuário logado (injetado por Middleware/JWT)
class UserContext(BaseModel):
    user_id: str
    company_id: str  # ID da empresa/tenant


# ==============================================================================
# DEPENDÊNCIAS FAKE PARA CONTEXTO DE EXECUÇÃO
# ==============================================================================

async def get_db_session() -> AsyncSession:
    """Retorna uma sessão do banco de dados (Injeção de dependência)."""
    raise NotImplementedError("Conexão com BD deve ser provida pela aplicação.")


async def get_current_user() -> UserContext:
    """Extrai o usuário logado e sua respectiva empresa (Tenant) a partir do JWT."""
    # Exemplo mockado
    return UserContext(user_id="usr_123", company_id="comp_tenant_99")


# ==============================================================================
# ENDPOINT / ROTA
# ==============================================================================

router = APIRouter(prefix="/api/v1/subscription", tags=["Subscription"])


@router.post(
    "/redeem-coupon",
    response_model=RedeemCouponResponse,
    status_code=status.HTTP_200_OK,
    summary="Resgata um cupom de desconto para a assinatura da empresa")
async def redeem_coupon(
    payload: RedeemCouponRequest,
    current_user: UserContext = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)):
    company_id = current_user.company_id
    coupon_code = payload.code.strip().upper()

    # 1. Buscar a assinatura ativa vinculada ao Tenant
    stmt_sub = select(Subscription).where(Subscription.company_id == company_id)
    result_sub = await db.execute(stmt_sub)
    subscription = result_sub.scalars().first()

    if not subscription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assinatura não encontrada para esta empresa."
        )

    # 2. Buscar o cupom informado
    stmt_coupon = select(Coupon).where(Coupon.code == coupon_code)
    result_coupon = await db.execute(stmt_coupon)
    coupon = result_coupon.scalars().first()

    if not coupon or not coupon.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cupom inválido ou inativo."
        )

    # 3. Validar se o cupom expirou
    now = datetime.now(timezone.utc)
    if coupon.valid_until and coupon.valid_until < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este cupom promocional já expirou."
        )

    # 4. Validar limite de usos globais do cupom
    if coupon.max_uses is not None and coupon.uses_count >= coupon.max_uses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este cupom atingiu o limite máximo de resgates."
        )

    # 5. Verificar se o Tenant já utilizou este cupom no passado
    stmt_redemption = select(CouponRedemption).where(
        CouponRedemption.company_id == company_id,
        CouponRedemption.coupon_id == coupon.id
    )
    result_redemption = await db.execute(stmt_redemption)
    already_redeemed = result_redemption.scalars().first()

    if already_redeemed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Este cupom já foi aplicado anteriormente por esta empresa."
        )

    # 6. Calcular o valor do desconto e o valor atualizado da mensalidade
    base_price = Decimal(str(subscription.base_price))
    discount_value = Decimal(str(coupon.discount_value))

    if coupon.discount_type == DiscountType.PERCENTAGE:
        discount_amount = (base_price * discount_value) / Decimal("100")
    elif coupon.discount_type == DiscountType.FIXED_AMOUNT:
        discount_amount = discount_value
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Tipo de desconto inválido."
        )

    # Garante que o valor final da mensalidade nunca seja negativo
    new_price = max(Decimal("0.00"), base_price - discount_amount)
    effective_discount = base_price - new_price

    # 7. Atualizar dados no banco (Operação atômica na transação)
    subscription.current_price = new_price
    subscription.active_coupon_id = coupon.id
    coupon.uses_count += 1

    redemption_record = CouponRedemption(
        id=f"red_{company_id}_{coupon.id}_{int(now.timestamp())}",
        company_id=company_id,
        coupon_id=coupon.id,
        redeemed_at=now
    )
    db.add(redemption_record)

    await db.commit()
    await db.refresh(subscription)

    # 8. Retornar resposta
    return RedeemCouponResponse(
        message="Cupom resgatado e aplicado com sucesso!",
        company_id=company_id,
        original_price=base_price,
        discount_applied=effective_discount,
        updated_monthly_price=new_price,
        coupon_code=coupon.code
    )