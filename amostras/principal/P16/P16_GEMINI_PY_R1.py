from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

# ==============================================================================
# SCHEMAS (Pydantic)
# ==============================================================================

class RedeemCouponRequest(BaseModel):
    coupon_code: str

class RedeemCouponResponse(BaseModel):
    message: str
    coupon_code: str
    discount_applied: Decimal
    previous_monthly_fee: Decimal
    updated_monthly_fee: Decimal


# ==============================================================================
# MODELOS DE BANCO DE DADOS (Simulação de estrutura SQLAlchemy)
# ==============================================================================

"""
Modelos esperados no ecossistema da aplicação:

class Coupon(Base):
    __tablename__ = "coupons"
    id = Column(Integer, primary_key=True)
    code = Column(String, unique=True, index=True)
    discount_percentage = Column(Numeric(5, 2))  # Ex: 15.00 para 15%
    discount_fixed = Column(Numeric(10, 2))       # Ex: 50.00 para R$ 50 de desconto
    is_active = Column(Boolean, default=True)
    valid_until = Column(DateTime(timezone=True), nullable=True)
    max_uses = Column(Integer, nullable=True)
    current_uses = Column(Integer, default=0)

class Subscription(Base):
    __tablename__ = "subscriptions"
    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, index=True, nullable=False)
    monthly_fee = Column(Numeric(10, 2), nullable=False)
    coupon_id = Column(Integer, ForeignKey("coupons.id"), nullable=True)

class TenantCouponHistory(Base):
    __tablename__ = "tenant_coupon_history"
    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, index=True, nullable=False)
    coupon_id = Column(Integer, ForeignKey("coupons.id"), nullable=False)
    redeemed_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc))
"""


# ==============================================================================
# ROUTER & ENDPOINT
# ==============================================================================

router = APIRouter(prefix="/api/v1/subscription", tags=["Subscription"])

# Funções simuladas de injeção de dependência do FastAPI
def get_db():
    """Retorna uma sessão do SQLAlchemy."""
    pass

def get_current_tenant_id() -> int:
    """
    Extrai e valida o tenant_id do token JWT do usuário autenticado,
    garantindo que um locatário só acesse seus próprios dados.
    """
    pass


@router.post(
    "/redeem-coupon",
    response_model=RedeemCouponResponse,
    status_code=status.HTTP_200_OK,
    summary="Resgatar cupom promocional para a assinatura do Tenant")
def redeem_coupon(
    payload: RedeemCouponRequest,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id)):
    code_normalized = payload.coupon_code.strip().upper()

    # 1. Buscar o cupom
    coupon = db.execute(
        select(Coupon).where(Coupon.code == code_normalized)
    ).scalar_one_or_none()

    if not coupon:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cupom promocional inválido ou não encontrado."
        )

    # 2. Validações de negócio do cupom
    now = datetime.now(timezone.utc)

    if not coupon.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este cupom está inativo."
        )

    if coupon.valid_until and coupon.valid_until < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este cupom expirou."
        )

    if coupon.max_uses is not None and coupon.current_uses >= coupon.max_uses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este cupom atingiu o limite máximo de resgates."
        )

    # 3. Buscar a assinatura do tenant atual (Isolamento Multitenant)
    subscription = db.execute(
        select(Subscription).where(Subscription.tenant_id == tenant_id)
    ).scalar_one_or_none()

    if not subscription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assinatura não encontrada para este locatário."
        )

    # 4. Verificar se a empresa já utilizou este cupom específico
    already_used = db.execute(
        select(TenantCouponHistory).where(
            TenantCouponHistory.tenant_id == tenant_id,
            TenantCouponHistory.coupon_id == coupon.id
        )
    ).scalar_one_or_none()

    if already_used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Sua empresa já resgatou este cupom anteriormente."
        )

    # 5. Cálculo do desconto
    previous_fee = subscription.monthly_fee
    discount = Decimal("0.00")

    if coupon.discount_percentage:
        discount = (previous_fee * coupon.discount_percentage) / Decimal("100.00")
    elif coupon.discount_fixed:
        discount = coupon.discount_fixed

    # Garante que a mensalidade não seja menor que zero
    new_fee = max(Decimal("0.00"), previous_fee - discount)
    actual_discount = previous_fee - new_fee

    # 6. Atualização atômica do banco de dados
    try:
        # Atualiza o valor da assinatura
        subscription.monthly_fee = new_fee
        subscription.coupon_id = coupon.id

        # Incrementa o uso do cupom
        coupon.current_uses += 1

        # Registra o histórico de resgate
        history = TenantCouponHistory(
            tenant_id=tenant_id,
            coupon_id=coupon.id,
            redeemed_at=now
        )
        db.add(history)

        db.commit()
        db.refresh(subscription)

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao processar o resgate do cupom."
        )

    # 7. Retorno dos dados atualizados
    return RedeemCouponResponse(
        message="Cupom aplicado com sucesso!",
        coupon_code=coupon.code,
        discount_applied=round(actual_discount, 2),
        previous_monthly_fee=round(previous_fee, 2),
        updated_monthly_fee=round(new_fee, 2)
    )