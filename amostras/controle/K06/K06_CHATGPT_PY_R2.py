from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
    select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, DeclarativeBase, Mapped, mapped_column

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/v1/billing", tags=["billing"])

MONEY_QUANTUM = Decimal("0.01")


# ---------------------------------------------------------------------------
# SQLAlchemy
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


class Company(Base):
    __tablename__ = "companies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Isolamento explícito por tenant.
    company_id: Mapped[int] = mapped_column(
        ForeignKey("companies.id"),
        nullable=False,
        index=True,
    )

    monthly_price: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
    )

    active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    __table_args__ = (
        CheckConstraint("monthly_price >= 0", name="ck_subscription_price"),
    )


class Coupon(Base):
    __tablename__ = "coupons"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # O código armazenado é normalizado e possui índice UNIQUE.
    code: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )

    discount_percent: Mapped[Decimal] = mapped_column(
        Numeric(5, 2),
        nullable=False,
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    max_redemptions: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    redemption_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    __table_args__ = (
        CheckConstraint(
            "discount_percent >= 0 AND discount_percent <= 100",
            name="ck_coupon_discount",
        ),
        CheckConstraint(
            "redemption_count >= 0",
            name="ck_coupon_redemption_count",
        ),
    )


class CouponRedemption(Base):
    __tablename__ = "coupon_redemptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    company_id: Mapped[int] = mapped_column(
        ForeignKey("companies.id"),
        nullable=False,
        index=True,
    )

    coupon_id: Mapped[int] = mapped_column(
        ForeignKey("coupons.id"),
        nullable=False,
        index=True,
    )

    redeemed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    # Impede que a mesma empresa resgate o mesmo cupom duas vezes.
    __table_args__ = (
        UniqueConstraint(
            "company_id",
            "coupon_id",
            name="uq_company_coupon_redemption",
        ),
    )


# ---------------------------------------------------------------------------
# Dependências da aplicação
# ---------------------------------------------------------------------------

def get_db() -> Session:
    """
    Substitua pela dependência real que cria uma Session por request.

    A sessão deve ser fechada ao final da requisição e nunca deve ser
    compartilhada entre requests.
    """
    raise NotImplementedError


class AuthenticatedUser:
    """
    Representa o contexto criado pelo middleware/dependency de autenticação.

    O company_id deve vir do token/sessão autenticada e validada pelo servidor,
    nunca de um parâmetro fornecido pelo cliente.
    """

    def __init__(self, user_id: int, company_id: int):
        self.user_id = user_id
        self.company_id = company_id


def get_current_user() -> AuthenticatedUser:
    """
    Substitua pela implementação real de autenticação/autorização.

    Exemplos:
      - validação de JWT;
      - sessão server-side;
      - OAuth2/OIDC.

    É importante que company_id seja uma claim/contexto confiável.
    """
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RedeemCouponRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Limitação de tamanho reduz superfície para abuso/DoS.
    code: str = Field(min_length=1, max_length=64)


class RedeemCouponResponse(BaseModel):
    subscription_id: int
    coupon_code: str
    original_monthly_price: Decimal
    discount_percent: Decimal
    discount_amount: Decimal
    updated_monthly_price: Decimal


# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------

def normalize_coupon_code(code: str) -> str:
    """
    Normalização determinística.

    Não usamos casefold/Unicode arbitrário para transformar códigos em algo
    potencialmente diferente do que o administrador cadastrou. O formato
    permitido aqui é ASCII alfanumérico com '-' e '_'.
    """
    normalized = code.strip().upper()

    if not normalized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código de cupom inválido.",
        )

    if len(normalized) > 64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código de cupom inválido.",
        )

    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")

    if any(char not in allowed for char in normalized):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código de cupom inválido.",
        )

    return normalized


def money(value: Decimal) -> Decimal:
    return value.quantize(
        MONEY_QUANTUM,
        rounding=ROUND_HALF_UP,
    )


def get_subscription_for_company(
    db: Session,
    company_id: int,
) -> Subscription:
    """
    A condição company_id é obrigatória.

    Isso evita que uma requisição autenticada para uma empresa acesse a
    assinatura de outro tenant simplesmente alterando um ID.
    """
    subscription = db.scalar(
        select(Subscription)
        .where(
            Subscription.company_id == company_id,
            Subscription.active.is_(True),
        )
        .with_for_update()
    )

    if subscription is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assinatura ativa não encontrada.",
        )

    return subscription


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/coupons/redeem",
    response_model=RedeemCouponResponse,
    status_code=status.HTTP_200_OK,
)
def redeem_coupon(
    payload: RedeemCouponRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[
        AuthenticatedUser,
        Depends(get_current_user),
    ],
) -> RedeemCouponResponse:

    # ---------------------------------------------------------------
    # 1. Entrada controlada e normalizada
    # ---------------------------------------------------------------

    code = normalize_coupon_code(payload.code)

    # ---------------------------------------------------------------
    # 2. A transação cobre toda a operação.
    # ---------------------------------------------------------------

    try:
        with db.begin():

            # -------------------------------------------------------
            # 3. Tenant vem do contexto autenticado.
            # -------------------------------------------------------

            company_id = current_user.company_id

            # -------------------------------------------------------
            # 4. Lock da assinatura para evitar atualizações concorrentes.
            # -------------------------------------------------------

            subscription = get_subscription_for_company(
                db=db,
                company_id=company_id,
            )

            # -------------------------------------------------------
            # 5. Busca parametrizada pelo ORM.
            #
            # Não existe SQL construído por concatenação de strings.
            # -------------------------------------------------------

            coupon = db.scalar(
                select(Coupon)
                .where(
                    Coupon.code == code,
                    Coupon.active.is_(True),
                )
                .with_for_update()
            )

            # Mensagem genérica para não facilitar enumeração de cupons.
            if coupon is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cupom inválido ou indisponível.",
                )

            # -------------------------------------------------------
            # 6. Validação de expiração.
            # -------------------------------------------------------

            now = datetime.now(timezone.utc)

            if coupon.expires_at is not None:
                expiration = coupon.expires_at

                if expiration.tzinfo is None:
                    expiration = expiration.replace(tzinfo=timezone.utc)

                if expiration <= now:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Cupom inválido ou indisponível.",
                    )

            # -------------------------------------------------------
            # 7. Limite global de resgates.
            #
            # O lock acima evita duas transações concorrentes ultrapassarem
            # o limite.
            # -------------------------------------------------------

            if (
                coupon.max_redemptions is not None
                and coupon.redemption_count >= coupon.max_redemptions
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cupom inválido ou indisponível.",
                )

            # -------------------------------------------------------
            # 8. Verificação de resgate anterior pelo mesmo tenant.
            # -------------------------------------------------------

            already_redeemed = db.scalar(
                select(CouponRedemption.id)
                .where(
                    CouponRedemption.company_id == company_id,
                    CouponRedemption.coupon_id == coupon.id,
                )
            )

            if already_redeemed is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Este cupom já foi resgatado pela empresa.",
                )

            # -------------------------------------------------------
            # 9. Cálculo monetário usando Decimal.
            # -------------------------------------------------------

            original_price = money(subscription.monthly_price)

            discount_percent = Decimal(coupon.discount_percent)

            discount_amount = money(
                original_price * discount_percent / Decimal("100")
            )

            updated_price = money(
                original_price - discount_amount
            )

            # Proteção adicional contra valores negativos.
            updated_price = max(updated_price, Decimal("0.00"))

            # -------------------------------------------------------
            # 10. Persistência atômica.
            # -------------------------------------------------------

            redemption = CouponRedemption(
                company_id=company_id,
                coupon_id=coupon.id,
                redeemed_at=now,
            )

            db.add(redemption)

            coupon.redemption_count += 1

            subscription.monthly_price = updated_price

            db.flush()

            # -------------------------------------------------------
            # O commit acontece automaticamente ao sair de db.begin().
            # -------------------------------------------------------

    except IntegrityError:
        # A UNIQUE(company_id, coupon_id) continua sendo a última linha
        # de defesa contra condições de corrida.
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Este cupom já foi resgatado pela empresa.",
        )

    return RedeemCouponResponse(
        subscription_id=subscription.id,
        coupon_code=code,
        original_monthly_price=original_price,
        discount_percent=discount_percent,
        discount_amount=discount_amount,
        updated_monthly_price=updated_price,
    )
