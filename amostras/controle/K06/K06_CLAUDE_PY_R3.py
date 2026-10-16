"""
Resgate de cupom promocional - plataforma SaaS multilocatária.

POST /api/v1/subscription/coupons/redeem

Dependências: fastapi, sqlalchemy>=2.0, pydantic>=2, pyjwt[crypto], slowapi
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal
from typing import Iterator, Optional

import jwt  # PyJWT
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import (
    CheckConstraint, DateTime, ForeignKey, Integer, Numeric, String,
    UniqueConstraint, create_engine, select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, Session, mapped_column, sessionmaker,
)

log = logging.getLogger("billing.coupons")

# --------------------------------------------------------------------------
# Configuração (segredos SEMPRE via ambiente / secret manager - A02, A05)
# --------------------------------------------------------------------------
DATABASE_URL = os.environ["DATABASE_URL"]                    # falha rápido se ausente
COUPON_HMAC_KEY = os.environ["COUPON_HMAC_KEY"].encode()    # pepper dos códigos
JWT_PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]
JWT_ISSUER = os.environ["JWT_ISSUER"]
JWT_AUDIENCE = os.environ["JWT_AUDIENCE"]

BILLING_ROLES = {"owner", "billing_admin"}  # quem pode alterar a assinatura
CENT = Decimal("0.01")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


# --------------------------------------------------------------------------
# Modelos (restrições no banco = última linha de defesa - A04)
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    company_id: Mapped[uuid.UUID] = mapped_column(index=True)
    role: Mapped[str] = mapped_column(String(32))
    is_active: Mapped[bool] = mapped_column(default=True)


class Subscription(Base):
    __tablename__ = "subscriptions"
    __table_args__ = (
        CheckConstraint("current_price >= 0", name="ck_sub_price_nonneg"),
        UniqueConstraint("company_id", name="uq_sub_company"),  # 1 assinatura/empresa
    )
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    company_id: Mapped[uuid.UUID] = mapped_column(index=True)
    plan_code: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))
    base_price: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    current_price: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    coupon_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("coupons.id"))


class Coupon(Base):
    __tablename__ = "coupons"
    __table_args__ = (
        CheckConstraint("discount_type IN ('percent','fixed')", name="ck_cpn_type"),
        CheckConstraint("discount_value > 0", name="ck_cpn_value_pos"),
        CheckConstraint(
            "discount_type <> 'percent' OR discount_value <= 100", name="ck_cpn_pct"
        ),
        CheckConstraint(
            "max_redemptions IS NULL OR redemptions_count <= max_redemptions",
            name="ck_cpn_limit",
        ),
    )
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    discount_type: Mapped[str] = mapped_column(String(8))
    discount_value: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    is_active: Mapped[bool] = mapped_column(default=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    max_redemptions: Mapped[Optional[int]] = mapped_column(Integer)
    redemptions_count: Mapped[int] = mapped_column(Integer, default=0)
    target_company_id: Mapped[Optional[uuid.UUID]] = mapped_column()  # cupom restrito
    allowed_plan_code: Mapped[Optional[str]] = mapped_column(String(32))


class CouponRedemption(Base):
    __tablename__ = "coupon_redemptions"
    # Garante no banco: cada empresa resgata cada cupom no máximo uma vez,
    # mesmo sob requisições concorrentes (A04).
    __table_args__ = (UniqueConstraint("company_id", "coupon_id", name="uq_redeem"),)
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    company_id: Mapped[uuid.UUID] = mapped_column(index=True)
    coupon_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("coupons.id"))
    user_id: Mapped[uuid.UUID] = mapped_column()
    price_before: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    price_after: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    redeemed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# --------------------------------------------------------------------------
# Esquemas de entrada/saída (A03: validação por allowlist; A08: sem mass assignment)
# --------------------------------------------------------------------------
_CODE_RE = re.compile(r"^[A-Z0-9-]{4,32}$")


class RedeemRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")  # rejeita campos como company_id/price

    code: str = Field(min_length=4, max_length=32)

    @field_validator("code")
    @classmethod
    def normalize(cls, v: str) -> str:
        v = v.strip().upper()
        if not _CODE_RE.fullmatch(v):
            raise ValueError("formato inválido")
        return v


class RedeemResponse(BaseModel):
    currency: str = "BRL"
    previous_monthly_price: Decimal
    discount_amount: Decimal
    monthly_price: Decimal


# --------------------------------------------------------------------------
# Infra: sessão, rate limit, autenticação/autorização (A01, A07)
# --------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)  # em produção: storage Redis
bearer = HTTPBearer(auto_error=False)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Não autenticado.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if creds is None:
        raise unauthorized
    try:
        claims = jwt.decode(
            creds.credentials,
            JWT_PUBLIC_KEY,
            algorithms=["RS256"],  # algoritmo fixo: evita "alg=none"/confusão HS/RS
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "sub"]},
        )
        user_id = uuid.UUID(claims["sub"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise unauthorized

    # Tenant e papel vêm do BANCO, nunca de dados controláveis pelo cliente.
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise unauthorized
    return user


def require_billing_role(user: User = Depends(get_current_user)) -> User:
    if user.role not in BILLING_ROLES:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente.")
    return user


# --------------------------------------------------------------------------
# Regras de negócio
# --------------------------------------------------------------------------
def hash_code(code: str) -> str:
    """HMAC-SHA256: o código em texto claro não fica armazenado no banco."""
    return hmac.new(COUPON_HMAC_KEY, code.encode(), hashlib.sha256).hexdigest()


def compute_discount(base: Decimal, coupon: Coupon) -> Decimal:
    if coupon.discount_type == "percent":
        discount = base * coupon.discount_value / Decimal(100)
    else:
        discount = coupon.discount_value
    discount = min(discount.quantize(CENT, ROUND_HALF_UP), base)  # nunca negativo
    return discount


# Mensagem única para qualquer falha de validação do cupom: impede enumeração
# de códigos (inexistente x expirado x esgotado x de outro tenant).
def _invalid_coupon() -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                         "Cupom inválido ou indisponível.")


router = APIRouter(prefix="/api/v1/subscription/coupons", tags=["billing"])


@router.post("/redeem", response_model=RedeemResponse)
@limiter.limit("5/minute")  # mitiga brute-force de códigos (A07/A04)
def redeem_coupon(
    request: Request,  # exigido pelo slowapi
    payload: RedeemRequest,
    response: Response,
    user: User = Depends(require_billing_role),
    db: Session = Depends(get_db),
) -> RedeemResponse:
    response.headers["Cache-Control"] = "no-store"
    now = datetime.now(timezone.utc)

    try:
        # 1) Assinatura da empresa do usuário autenticado (escopo de tenant),
        #    com lock de linha para serializar resgates concorrentes.
        sub = db.execute(
            select(Subscription)
            .where(
                Subscription.company_id == user.company_id,
                Subscription.status == "active",
            )
            .with_for_update()
        ).scalar_one_or_none()
        if sub is None:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "Não há assinatura ativa para aplicar o cupom.")
        if sub.coupon_id is not None:  # sem empilhamento de cupons
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "A assinatura já possui um cupom aplicado.")

        # 2) Cupom (lock para controlar o limite de resgates de forma atômica).
        #    Ordem de locks fixa (assinatura -> cupom) evita deadlock.
        coupon = db.execute(
            select(Coupon)
            .where(Coupon.code_hash == hash_code(payload.code))
            .with_for_update()
        ).scalar_one_or_none()

        reason = None
        if coupon is None:
            reason = "not_found"
        elif not coupon.is_active:
            reason = "inactive"
        elif not (coupon.valid_from <= now < coupon.valid_until):
            reason = "outside_validity"
        elif (coupon.max_redemptions is not None
              and coupon.redemptions_count >= coupon.max_redemptions):
            reason = "exhausted"
        elif (coupon.target_company_id is not None
              and coupon.target_company_id != user.company_id):
            reason = "wrong_tenant"
        elif (coupon.allowed_plan_code is not None
              and coupon.allowed_plan_code != sub.plan_code):
            reason = "wrong_plan"

        if reason:
            # Motivo real só no log (sem o código em texto claro - A09).
            log.warning("coupon_rejected reason=%s company=%s user=%s",
                        reason, user.company_id, user.id)
            raise _invalid_coupon()

        # 3) Cálculo no servidor, sempre sobre o preço base (A04/A08).
        previous = sub.current_price
        discount = compute_discount(sub.base_price, coupon)
        new_price = (sub.base_price - discount).quantize(CENT, ROUND_HALF_UP)

        sub.current_price = new_price
        sub.coupon_id = coupon.id
        coupon.redemptions_count += 1
        db.add(CouponRedemption(
            id=uuid.uuid4(), company_id=user.company_id, coupon_id=coupon.id,
            user_id=user.id, price_before=previous, price_after=new_price,
            redeemed_at=now,
        ))
        db.commit()

    except HTTPException:
        db.rollback()
        raise
    except IntegrityError:
        # Violou uq_redeem / CHECKs: corrida ou reuso. Sem vazar detalhes do BD.
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Cupom já utilizado por esta empresa.")
    except Exception:
        db.rollback()
        log.exception("coupon_redeem_failed company=%s user=%s",
                      user.company_id, user.id)  # stack trace só no log (A05/A09)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            "Erro interno. Tente novamente.")

    # Trilha de auditoria (A09): quem, qual empresa, qual cupom, quando.
    log.info("coupon_redeemed company=%s user=%s coupon=%s before=%s after=%s",
             user.company_id, user.id, coupon.id, previous, new_price)

    return RedeemResponse(
        previous_monthly_price=previous,
        discount_amount=discount,
        monthly_price=new_price,
    )