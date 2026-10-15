from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

# -----------------------------------------------------------------------------
# Enums e Schemas Pydantic (DTOs)
# -----------------------------------------------------------------------------

class DiscountType(str, Enum):
    PERCENTAGE = "PERCENTAGE"
    FIXED_AMOUNT = "FIXED_AMOUNT"

class CouponRedeemRequest(BaseModel):
    code: str = Field(..., description="Código do cupom promocional", example="SUMMER2026")

class SubscriptionResponse(BaseModel):
    company_id: int
    plan_name: str
    original_price: float
    discount_applied: float
    final_price: float
    applied_coupon_code: str
    message: str

# -----------------------------------------------------------------------------
# DTO/Model Contextual do Usuário Autenticado (Injeção de Dependência)
# -----------------------------------------------------------------------------

class CurrentUser:
    """
    Representa o contexto de segurança extraído do Token JWT/Sessão.
    Garante o isolamento multilocatário (multitenant).
    """
    def __init__(self, user_id: int, company_id: int):
        self.user_id = user_id
        self.company_id = company_id

def get_current_user() -> CurrentUser:
    # Em produção, este método decodifica o JWT do Header 'Authorization'
    # Retornando mock para fins demonstrativos:
    return CurrentUser(user_id=10, company_id=42)

def get_db():
    # Injeção de dependência do banco de dados (Session SQLAlchemy)
    yield None

# -----------------------------------------------------------------------------
# Rota da API
# -----------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/subscriptions", tags=["Assinaturas"])

@router.post(
    "/redeem-coupon",
    response_model=SubscriptionResponse,
    status_code=status.HTTP_200_OK,
    summary="Resgata um cupom promocional e atualiza a mensalidade da empresa")
def redeem_coupon(
    payload: CouponRedeemRequest,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    coupon_code = payload.code.strip().upper()

    # 1. Buscar a assinatura ativa da empresa do usuário logado (Isolamento Tenant)
    # Exemplo SQLAlchemy: db.query(Subscription).filter_by(company_id=current_user.company_id, is_active=True).first()
    subscription = get_active_subscription_by_company(db, company_id=current_user.company_id)
    if not subscription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nenhuma assinatura ativa encontrada para esta empresa."
        )

    # 2. Buscar e validar o cupom promocional
    coupon = get_coupon_by_code(db, code=coupon_code)
    if not coupon or not coupon.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cupom promocional inválido ou inativo."
        )

    if coupon.expires_at and coupon.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este cupom promocional já expirou."
        )

    if coupon.max_uses is not None and coupon.current_uses >= coupon.max_uses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este cupom atingiu o limite máximo de resgates."
        )

    # 3. Validar se a empresa já utilizou este cupom anteriormente
    has_used = check_coupon_already_used(db, company_id=current_user.company_id, coupon_id=coupon.id)
    if has_used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Sua empresa já resgatou este cupom anteriormente."
        )

    # 4. Calcular o desconto e o novo valor
    original_price = float(subscription.price)

    if coupon.discount_type == DiscountType.PERCENTAGE:
        discount_amount = original_price * (coupon.discount_value / 100.0)
    elif coupon.discount_type == DiscountType.FIXED_AMOUNT:
        discount_amount = coupon.discount_value
    else:
        discount_amount = 0.0

    # Garante que o valor com desconto não seja menor que zero
    discount_amount = min(discount_amount, original_price)
    final_price = max(0.0, original_price - discount_amount)

    # 5. Persistir as alterações no Banco de Dados
    save_coupon_redemption(
        db=db,
        subscription=subscription,
        coupon=coupon,
        company_id=current_user.company_id,
        user_id=current_user.user_id,
        discount_amount=discount_amount,
        final_price=final_price
    )

    return SubscriptionResponse(
        company_id=current_user.company_id,
        plan_name=subscription.plan_name,
        original_price=round(original_price, 2),
        discount_applied=round(discount_amount, 2),
        final_price=round(final_price, 2),
        applied_coupon_code=coupon.code,
        message="Cupom aplicado com sucesso ao plano da empresa!"
    )


# -----------------------------------------------------------------------------
# Mocks da camada de persistência para demonstração de fluxo
# -----------------------------------------------------------------------------

def get_active_subscription_by_company(db, company_id: int):
    class MockSubscription:
        id = 100
        plan_name = "Plano Pro Enterprise"
        price = 299.90
        company_id = company_id
    return MockSubscription()

def get_coupon_by_code(db, code: str):
    if code == "SUMMER2026":
        class MockCoupon:
            id = 5
            code = "SUMMER2026"
            is_active = True
            discount_type = DiscountType.PERCENTAGE
            discount_value = 20.0  # 20%
            expires_at = None
            max_uses = 100
            current_uses = 10
        return MockCoupon()
    return None

def check_coupon_already_used(db, company_id: int, coupon_id: int) -> bool:
    return False

def save_coupon_redemption(db, subscription, coupon, company_id, user_id, discount_amount, final_price):
    # Atualiza o preço/cupom na assinatura
    # Decrementa/incrementa os contadores do cupom
    # Cria registro no histórico de resgates de cupons (Audit Log)
    pass