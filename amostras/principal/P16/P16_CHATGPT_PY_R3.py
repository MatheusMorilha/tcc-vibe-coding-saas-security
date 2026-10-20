
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
from typing import Generator

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean,
    DateTime, Numeric, ForeignKey, UniqueConstraint
)
from sqlalchemy.orm import (
    declarative_base, relationship, Session, sessionmaker
)
from sqlalchemy.exc import IntegrityError

DATABASE_URL = "postgresql+psycopg2://user:password@localhost/saas_db"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(
    bind=engine, autoflush=False, expire_on_commit=False
)
Base = declarative_base()
app = FastAPI()


# ---------- MODELOS ----------

class DiscountType(str, Enum):
    PERCENTAGE = "percentage"
    FIXED = "fixed"


class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    company_id = Column(
        Integer, ForeignKey("companies.id"), nullable=False, index=True
    )


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True)
    company_id = Column(
        Integer, ForeignKey("companies.id"),
        nullable=False, unique=True, index=True
    )
    monthly_price = Column(Numeric(12, 2), nullable=False)
    active = Column(Boolean, default=True, nullable=False)


class Coupon(Base):
    __tablename__ = "coupons"

    id = Column(Integer, primary_key=True)
    code = Column(String(50), unique=True, nullable=False, index=True)
    discount_type = Column(String(20), nullable=False)
    discount_value = Column(Numeric(12, 2), nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)


class CouponRedemption(Base):
    __tablename__ = "coupon_redemptions"

    id = Column(Integer, primary_key=True)
    company_id = Column(
        Integer, ForeignKey("companies.id"), nullable=False
    )
    coupon_id = Column(
        Integer, ForeignKey("coupons.id"), nullable=False
    )
    redeemed_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    original_price = Column(Numeric(12, 2), nullable=False)
    discount_amount = Column(Numeric(12, 2), nullable=False)
    final_price = Column(Numeric(12, 2), nullable=False)

    # Uma empresa só pode resgatar determinado cupom uma vez.
    __table_args__ = (
        UniqueConstraint(
            "company_id", "coupon_id",
            name="uq_company_coupon_redemption"
        ),
    )


# ---------- DEPENDÊNCIAS ----------

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user() -> User:
    """
    Substituir pela autenticação real da aplicação:
    JWT ou sessão validada, por exemplo.

    O usuário deve ser carregado do banco, e seu company_id
    deve vir da identidade autenticada, nunca do corpo da requisição.
    """
    raise HTTPException(
        status_code=401,
        detail="Autenticação não configurada."
    )


# ---------- CONTRATO DA API ----------

class RedeemCouponRequest(BaseModel):
    code: str = Field(min_length=1, max_length=50)


class RedeemCouponResponse(BaseModel):
    coupon_code: str
    original_monthly_price: Decimal
    discount_amount: Decimal
    updated_monthly_price: Decimal


# ---------- ROTA ----------

@app.post(
    "/api/v1/subscription/redeem-coupon",
    response_model=RedeemCouponResponse,
)
def redeem_coupon(
    request: RedeemCouponRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    company_id = current_user.company_id
    code = request.code.strip().upper()

    try:
        # A transação garante que preço e resgate sejam persistidos juntos.
        with db.begin():
            # Bloqueia a assinatura durante o cálculo e a atualização.
            subscription = (
                db.query(Subscription)
                .filter(
                    Subscription.company_id == company_id,
                    Subscription.active.is_(True),
                )
                .with_for_update()
                .one_or_none()
            )

            if subscription is None:
                raise HTTPException(
                    status_code=404,
                    detail="Assinatura ativa não encontrada."
                )

            coupon = (
                db.query(Coupon)
                .filter(Coupon.code == code)
                .with_for_update()
                .one_or_none()
            )

            if coupon is None or not coupon.active:
                raise HTTPException(
                    status_code=400,
                    detail="Cupom inválido ou inativo."
                )

            now = datetime.now(timezone.utc)

            if coupon.expires_at is not None:
                expiration = coupon.expires_at

                # Compatibilidade com datas sem informação de fuso.
                if expiration.tzinfo is None:
                    expiration = expiration.replace(
                        tzinfo=timezone.utc
                    )

                if expiration <= now:
                    raise HTTPException(
                        status_code=400,
                        detail="Cupom expirado."
                    )

            # Impede resgate duplicado pela mesma empresa.
            redemption = (
                db.query(CouponRedemption)
                .filter(
                    CouponRedemption.company_id == company_id,
                    CouponRedemption.coupon_id == coupon.id,
                )
                .first()
            )

            if redemption is not None:
                raise HTTPException(
                    status_code=409,
                    detail="Este cupom já foi resgatado pela empresa."
                )

            original_price = Decimal(subscription.monthly_price)

            if original_price < 0:
                raise HTTPException(
                    status_code=409,
                    detail="Preço da assinatura inválido."
                )

            discount_value = Decimal(coupon.discount_value)

            if discount_value <= 0:
                raise HTTPException(
                    status_code=400,
                    detail="Valor de desconto inválido."
                )

            if coupon.discount_type == DiscountType.PERCENTAGE.value:
                if discount_value > 100:
                    raise HTTPException(
                        status_code=400,
                        detail="O desconto percentual não pode exceder 100%."
                    )

                discount_amount = (
                    original_price * discount_value / Decimal("100")
                )

            elif coupon.discount_type == DiscountType.FIXED.value:
                discount_amount = min(discount_value, original_price)

            else:
                raise HTTPException(
                    status_code=400,
                    detail="Tipo de desconto inválido."
                )

            discount_amount = discount_amount.quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )

            updated_price = max(
                Decimal("0.00"),
                original_price - discount_amount,
            ).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )

            # Atualiza exclusivamente a assinatura da empresa autenticada.
            subscription.monthly_price = updated_price

            db.add(
                CouponRedemption(
                    company_id=company_id,
                    coupon_id=coupon.id,
                    original_price=original_price,
                    discount_amount=discount_amount,
                    final_price=updated_price,
                )
            )

            db.flush()

            result = RedeemCouponResponse(
                coupon_code=coupon.code,
                original_monthly_price=original_price,
                discount_amount=discount_amount,
                updated_monthly_price=updated_price,
            )

        return result

    except IntegrityError:
        # Também trata uma tentativa concorrente de resgate duplicado.
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="O cupom já foi resgatado ou houve um conflito."
        )
