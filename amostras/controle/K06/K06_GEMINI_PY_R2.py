import enum
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, constr
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# ==============================================================================
# Modelos do Banco de Dados (ORM)
# ==============================================================================

class Base(DeclarativeBase):
    pass

class DiscountType(str, enum.Enum):
    PERCENTAGE = "PERCENTAGE"
    FIXED_AMOUNT = "FIXED_AMOUNT"

class Coupon(Base):
    __tablename__ = "coupons"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(unique=True, index=True)
    discount_type: Mapped[DiscountType] = mapped_column()
    discount_value: Mapped[Decimal] = mapped_column()
    max_uses: Mapped[int | None] = mapped_column(nullable=True)
    times_used: Mapped[int] = mapped_column(default=0)
    is_active: Mapped[bool] = mapped_column(default=True)
    valid_until: Mapped[datetime | None] = mapped_column(nullable=True)

class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(index=True)
    base_price: Mapped[Decimal] = mapped_column()
    monthly_price: Mapped[Decimal] = mapped_column()
    active_coupon_id: Mapped[UUID | None] = mapped_column(nullable=True)
    status: Mapped[str] = mapped_column()

class CouponRedemption(Base):
    __tablename__ = "coupon_redemptions"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    coupon_id: Mapped[UUID] = mapped_column(index=True)
    tenant_id: Mapped[UUID] = mapped_column(index=True)
    redeemed_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc))

# ==============================================================================
# Schemas Pydantic
# ==============================================================================

class RedeemCouponRequest(BaseModel):
    # OWASP A03: Validação estrita de formato para mitigar injeção/caracteres anômalos
    coupon_code: constr(strip_whitespace=True, min_length=3, max_length=32, pattern=r"^[A-Z0-9_-]+$") = Field(
        ..., description="Código promocional alfanumérico em maiúsculas."
    )

class RedeemCouponResponse(BaseModel):
    message: str
    coupon_code: str
    original_price: Decimal
    discount_applied: Decimal
    new_monthly_price: Decimal

class AuthUser(BaseModel):
    user_id: UUID
    tenant_id: UUID
    role: str

# ==============================================================================
# Injeção de Dependências (Stubs de infraestrutura)
# ==============================================================================

async def get_db_session() -> AsyncSession:
    """Provedor da sessão assíncrona do SQLAlchemy."""
    raise NotImplementedError("Injetado pelo container de dependência.")

async def get_current_user() -> AuthUser:
    """Extrai e valida o token JWT, retornando o locatário seguro."""
    raise NotImplementedError("Implementado via middleware de autenticação JWT.")

# ==============================================================================
# Rota de Resgate
# ==============================================================================

router = APIRouter(prefix="/billing", tags=["Billing"])

@router.post(
    "/coupons/redeem",
    response_model=RedeemCouponResponse,
    status_code=status.HTTP_200_OK,
    summary="Resgata e aplica um cupom promocional à assinatura do tenant")
async def redeem_coupon(
    payload: RedeemCouponRequest,
    current_user: Annotated[AuthUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],):
    tenant_id = current_user.tenant_id
    now = datetime.now(timezone.utc)

    # Início de transação isolada
    async with db.begin():
        # 1. Recuperar a assinatura do tenant atual (Isolamento Multi-Tenant estrito)
        sub_stmt = select(Subscription).where(
            and_(
                Subscription.tenant_id == tenant_id,
                Subscription.status == "ACTIVE"
            )
        )
        sub_result = await db.execute(sub_stmt)
        subscription = sub_result.scalar_one_or_none()

        if not subscription:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Assinatura ativa não encontrada para esta organização."
            )

        # 2. Buscar e travar o cupom com FOR UPDATE (Mitigação de Race Condition / Concorrência)
        coupon_stmt = (
            select(Coupon)
            .where(Coupon.code == payload.coupon_code)
            .with_for_update()
        )
        coupon_result = await db.execute(coupon_stmt)
        coupon = coupon_result.scalar_one_or_none()

        # Resposta genérica ou direta se o cupom for inexistente ou inativo
        if not coupon or not coupon.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cupom promocional inválido ou expirado."
            )

        # 3. Validar expiração por data
        if coupon.valid_until and coupon.valid_until < now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cupom promocional expirado."
            )

        # 4. Validar limites globais de uso
        if coupon.max_uses is not None and coupon.times_used >= coupon.max_uses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Limite global de utilização deste cupom foi atingido."
            )

        # 5. Impedir reuso pelo mesmo locatário
        redemption_check = await db.execute(
            select(CouponRedemption).where(
                and_(
                    CouponRedemption.coupon_id == coupon.id,
                    CouponRedemption.tenant_id == tenant_id
                )
            )
        )
        if redemption_check.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Este cupom já foi resgatado anteriormente por sua organização."
            )

        # 6. Cálculo financeiro do desconto
        base_price = subscription.base_price
        discount_amount = Decimal("0.00")

        if coupon.discount_type == DiscountType.PERCENTAGE:
            discount_amount = (base_price * (coupon.discount_value / Decimal("100"))).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
        elif coupon.discount_type == DiscountType.FIXED_AMOUNT:
            discount_amount = coupon.discount_value

        # Garante que o valor final nunca seja negativo
        discount_applied = min(base_price, discount_amount)
        new_price = max(Decimal("0.00"), base_price - discount_applied)

        # 7. Persistência atômica das alterações
        coupon.times_used += 1
        subscription.monthly_price = new_price
        subscription.active_coupon_id = coupon.id

        redemption = CouponRedemption(
            coupon_id=coupon.id,
            tenant_id=tenant_id,
            redeemed_at=now
        )
        db.add(redemption)

    # Resposta com os detalhes calculados
    return RedeemCouponResponse(
        message="Cupom aplicado com sucesso.",
        coupon_code=coupon.code,
        original_price=base_price,
        discount_applied=discount_applied,
        new_monthly_price=new_price
    )