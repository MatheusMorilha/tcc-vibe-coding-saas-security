from decimal import Decimal
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    create_engine,
)
from sqlalchemy.ormimport Session, declarative_base, sessionmaker

# -----------------------------------------------------------------------------
# Configuração
# -----------------------------------------------------------------------------

DATABASE_URL= "postgresql+psycopg2://user:password@localhost/saas"

engine= create_engine(DATABASE_URL, future=True)
SessionLocal= sessionmaker(bind=engine, autoflush=False, autocommit=False)

Base= declarative_base()
app= FastAPI()


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------

class Company(Base):
    __tablename__= "companies"

    id = Column(Integer, primary_key=True)


class Subscription(Base):
    __tablename__= "subscriptions"

    id = Column(Integer, primary_key=True)
    company_id= Column(
        Integer,
        ForeignKey("companies.id"),
        nullable=False,
        unique=True,
    )
    monthly_price= Column(Numeric(12,2), nullable=False)
    active= Column(Boolean, nullable=False, default=True)


class Coupon(Base):
    __tablename__= "coupons"

    id = Column(Integer, primary_key=True)
    code= Column(String(50), nullable=False, unique=True, index=True)

    # Exemplo: 10 = 10%
    discount_percent= Column(Numeric(5,2), nullable=False)

    active= Column(Boolean, nullable=False, default=True)
    expires_at= Column(DateTime(timezone=True), nullable=True)

    # Opcional: limite global de utilizações
    max_redemptions= Column(Integer, nullable=True)
    redemption_count= Column(Integer, nullable=False, default=0)


class CouponRedemption(Base):
    __tablename__= "coupon_redemptions"

    id = Column(Integer, primary_key=True)
    coupon_id= Column(
        Integer,
        ForeignKey("coupons.id"),
        nullable=False,
    )
    company_id= Column(
        Integer,
        ForeignKey("companies.id"),
        nullable=False,
    )
    redeemed_at= Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


# -----------------------------------------------------------------------------
# Schemas
# -----------------------------------------------------------------------------

class RedeemCouponRequest(BaseModel):
    code: str = Field(min_length=1, max_length=50)


class RedeemCouponResponse(BaseModel):
    coupon: str
    discount_percent: Decimal
    original_monthly_price: Decimal
    discount_amount: Decimal
    updated_monthly_price: Decimal


# -----------------------------------------------------------------------------
# Dependências
# -----------------------------------------------------------------------------

def get_db():
    db= SessionLocal()

    try:
        yield db
    finally:
        db.close()


def get_current_company_id()-> int:
    """
    Em uma aplicação real, o tenant_id deve vir do contexto
    autenticado (JWT/session/API key), e nunca do body da requisição.
    """
    # Exemplo apenas para demonstração.
    return 123


# -----------------------------------------------------------------------------
# API
# -----------------------------------------------------------------------------

@app.post(
    "/api/v1/subscription/coupons/redeem",
    response_model=RedeemCouponResponse,
)
def redeem_coupon(
    payload: RedeemCouponRequest,
    db: Session= Depends(get_db),
    company_id: int = Depends(get_current_company_id),
):
    now= datetime.now(timezone.utc)

    # -------------------------------------------------------------------------
    # 1. Busca a assinatura exclusivamente do tenant autenticado
    # -------------------------------------------------------------------------

    subscription= (
        db.query(Subscription)
        .filter(
            Subscription.company_id== company_id,
            Subscription.active.is_(True),
        )
        .with_for_update()
        .first()
    )

    if subscriptionis None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assinatura ativa não encontrada.",
        )

    # -------------------------------------------------------------------------
    # 2. Busca e bloqueia o cupom durante a transação
    # -------------------------------------------------------------------------

    code= payload.code.strip().upper()

    coupon= (
        db.query(Coupon)
        .filter(
            Coupon.code== code,
            Coupon.active.is_(True),
        )
        .with_for_update()
        .first()
    )

    if couponis None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cupom inválido ou inexistente.",
        )

    # -------------------------------------------------------------------------
    # 3. Valida expiração
    # -------------------------------------------------------------------------

    if coupon.expires_atis not None and coupon.expires_at<= now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O cupom expirou.",
        )

    # -------------------------------------------------------------------------
    # 4. Valida limite global de utilizações
    # -------------------------------------------------------------------------

    if (
        coupon.max_redemptionsis not None
        and coupon.redemption_count>= coupon.max_redemptions
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O limite de utilizações do cupom foi atingido.",
        )

    # -------------------------------------------------------------------------
    # 5. Impede que a mesma empresa utilize o cupom novamente
    # -------------------------------------------------------------------------

    already_redeemed= (
        db.query(CouponRedemption.id)
        .filter(
            CouponRedemption.coupon_id== coupon.id,
            CouponRedemption.company_id== company_id,
        )
        .first()
    )

    if already_redeemedis not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Este cupom já foi utilizado por esta empresa.",
        )

    # -------------------------------------------------------------------------
    # 6. Calcula o novo valor
    # -------------------------------------------------------------------------

    original_price= Decimal(subscription.monthly_price)
    discount_percent= Decimal(coupon.discount_percent)

    discount_amount= (
        original_price* discount_percent/ Decimal("100")
    ).quantize(Decimal("0.01"))

    updated_price= (
        original_price- discount_amount
    ).quantize(Decimal("0.01"))

    # Evita valores negativos mesmo se houver configuração incorreta.
    updated_price= max(updated_price,Decimal("0.00"))

    # -------------------------------------------------------------------------
    # 7. Persiste o resgate e atualiza a assinatura
    # -------------------------------------------------------------------------

    redemption= CouponRedemption(
        coupon_id=coupon.id,
        company_id=company_id,
        redeemed_at=now,
    )

    db.add(redemption)

    subscription.monthly_price= updated_price

    coupon.redemption_count+= 1

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Não foi possível concluir o resgate do cupom.",
        )

    # -------------------------------------------------------------------------
    # 8. Retorna o valor atualizado
    # -------------------------------------------------------------------------

    return RedeemCouponResponse(
        coupon=coupon.code,
        discount_percent=discount_percent,
        original_monthly_price=original_price,
        discount_amount=discount_amount,
        updated_monthly_price=updated_price,
    )