"""
POST /api/v1/subscription/coupons/redeem

Resgata um cupom promocional para a assinatura da empresa do usuário autenticado
e retorna o valor atualizado da mensalidade.

Dependências: fastapi, sqlalchemy>=2, pydantic>=2, pyjwt, redis
"""
from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal
from typing import Annotated, Generator

import jwt
import redis
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    Boolean, CheckConstraint, DateTime, ForeignKey, Integer, Numeric, String,
    UniqueConstraint, create_engine, select, update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

# --------------------------------------------------------------------------
# Configuração (A05): segredos só via ambiente; falha ao subir se ausentes.
# --------------------------------------------------------------------------
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ISSUER = os.environ["JWT_ISSUER"]
JWT_AUDIENCE = os.environ["JWT_AUDIENCE"]
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ["REDIS_URL"]

ALLOWED_ROLES = {"owner", "billing_admin"}   # quem pode alterar cobrança
RATE_LIMIT_MAX = 5                            # tentativas por janela, por usuário
RATE_LIMIT_WINDOW_S = 15 * 60
CENT = Decimal("0.01")

audit_log = logging.getLogger("audit.coupons")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)
redis_client = redis.Redis.from_url(REDIS_URL, socket_timeout=1)
bearer = HTTPBearer(auto_error=False)


# --------------------------------------------------------------------------
# Modelos
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    role: Mapped[str] = mapped_column(String(32))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class Subscription(Base):
    __tablename__ = "subscriptions"
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    plan_id: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))
    currency: Mapped[str] = mapped_column(String(3), default="BRL")
    list_price: Mapped[Decimal] = mapped_column(Numeric(12, 2))      # preço de tabela
    monthly_price: Mapped[Decimal] = mapped_column(Numeric(12, 2))   # preço efetivo
    coupon_id: Mapped[int | None] = mapped_column(ForeignKey("coupons.id"), nullable=True)
    __table_args__ = (CheckConstraint("monthly_price >= 0", name="ck_sub_price_nonneg"),)


class Coupon(Base):
    __tablename__ = "coupons"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(32), unique=True)       # armazenado em MAIÚSCULAS
    discount_type: Mapped[str] = mapped_column(String(8))            # "PERCENT" | "FIXED"
    discount_value: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    plan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)  # restrição de plano
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    max_redemptions: Mapped[int | None] = mapped_column(Integer, nullable=True)
    redemptions_count: Mapped[int] = mapped_column(Integer, default=0)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    __table_args__ = (
        CheckConstraint("discount_value > 0", name="ck_coupon_value_pos"),
        CheckConstraint(
            "discount_type <> 'PERCENT' OR discount_value <= 100", name="ck_coupon_pct"
        ),
    )


class CouponRedemption(Base):
    __tablename__ = "coupon_redemptions"
    id: Mapped[int] = mapped_column(primary_key=True)
    coupon_id: Mapped[int] = mapped_column(ForeignKey("coupons.id"))
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    subscription_id: Mapped[int] = mapped_column(ForeignKey("subscriptions.id"))
    redeemed_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    redeemed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    price_before: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    price_after: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    # Garante no banco: um cupom por empresa (protege contra corrida / replay).
    __table_args__ = (UniqueConstraint("company_id", "coupon_id", name="uq_company_coupon"),)


# --------------------------------------------------------------------------
# Schemas (A03/A04): validação estrita; company_id NUNCA vem do cliente.
# --------------------------------------------------------------------------
class RedeemRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    code: str = Field(min_length=4, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")


class RedeemResponse(BaseModel):
    currency: str
    previous_monthly_price: Decimal
    discount_amount: Decimal
    new_monthly_price: Decimal


# --------------------------------------------------------------------------
# Dependências: banco, autenticação, autorização, rate limit
# --------------------------------------------------------------------------
def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session


def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """A07: valida JWT (algoritmo fixo, exp/iss/aud obrigatórios) e recarrega o usuário
    do banco. O tenant vem do registro do usuário, não de claim ou parâmetro."""
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED, "Não autenticado.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if creds is None:
        raise unauthorized
    try:
        claims = jwt.decode(
            creds.credentials, JWT_SECRET, algorithms=["HS256"],
            issuer=JWT_ISSUER, audience=JWT_AUDIENCE,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
        user = db.get(User, int(claims["sub"]))
    except (jwt.PyJWTError, ValueError, TypeError):
        raise unauthorized
    if user is None or not user.is_active:
        raise unauthorized
    return user


def require_billing_role(user: Annotated[User, Depends(get_current_user)]) -> User:
    """A01: controle de acesso por função (apenas quem administra a cobrança)."""
    if user.role not in ALLOWED_ROLES:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente.")
    return user


def coupon_rate_limit(user: Annotated[User, Depends(require_billing_role)]) -> User:
    """A04/A07: limita tentativas para impedir enumeração/força bruta de cupons.
    Falha fechada se o Redis estiver indisponível."""
    key = f"rl:coupon:{user.company_id}:{user.id}"
    try:
        pipe = redis_client.pipeline()
        pipe.incr(key)
        pipe.expire(key, RATE_LIMIT_WINDOW_S, nx=True)
        attempts, _ = pipe.execute()
    except redis.RedisError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Serviço indisponível.")
    if attempts > RATE_LIMIT_MAX:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Muitas tentativas. Tente mais tarde.",
            headers={"Retry-After": str(RATE_LIMIT_WINDOW_S)},
        )
    return user


# --------------------------------------------------------------------------
# Regra de negócio
# --------------------------------------------------------------------------
INVALID_COUPON = HTTPException(
    status.HTTP_422_UNPROCESSABLE_ENTITY, "Cupom inválido ou indisponível."
)  # mensagem única: não revela se o código existe, expirou ou esgotou (A04)


def compute_price(list_price: Decimal, discount_type: str, value: Decimal) -> Decimal:
    """Cálculo 100% no servidor, sempre sobre o preço de tabela (sem empilhar descontos)."""
    discount = list_price * value / Decimal(100) if discount_type == "PERCENT" else value
    discount = min(discount, list_price)  # nunca negativo
    return (list_price - discount).quantize(CENT, rounding=ROUND_HALF_UP)


def _code_fingerprint(code: str) -> str:
    # A09: não registrar o código em claro nos logs.
    return hashlib.sha256(code.encode()).hexdigest()[:12]


router = APIRouter(prefix="/api/v1/subscription/coupons", tags=["subscription"])


@router.post("/redeem", response_model=RedeemResponse)
def redeem_coupon(
    body: RedeemRequest,
    request: Request,
    response: Response,
    user: Annotated[User, Depends(coupon_rate_limit)],
    db: Annotated[Session, Depends(get_db)],
) -> RedeemResponse:
    response.headers["Cache-Control"] = "no-store"
    code = body.code.upper()
    now = datetime.now(timezone.utc)
    fingerprint = _code_fingerprint(code)
    client_ip = request.client.host if request.client else "unknown"

    def log(outcome: str, **extra: object) -> None:
        audit_log.info(
            "coupon_redeem outcome=%s user=%s company=%s code_fp=%s ip=%s %s",
            outcome, user.id, user.company_id, fingerprint, client_ip, extra or "",
        )

    try:
        # 1) Trava a assinatura DA EMPRESA do usuário (filtro de tenant em toda consulta).
        sub = db.execute(
            select(Subscription)
            .where(Subscription.company_id == user.company_id, Subscription.status == "active")
            .with_for_update()
        ).scalar_one_or_none()
        if sub is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Assinatura ativa não encontrada.")
        if sub.coupon_id is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "A assinatura já possui um cupom aplicado.")

        # 2) Localiza e valida o cupom (consulta parametrizada via ORM: A03).
        coupon = db.execute(select(Coupon).where(Coupon.code == code)).scalar_one_or_none()
        if (
            coupon is None
            or not coupon.active
            or not (coupon.valid_from <= now <= coupon.valid_until)
            or (coupon.plan_id is not None and coupon.plan_id != sub.plan_id)
        ):
            log("rejected")
            raise INVALID_COUPON

        # 3) Consumo atômico do limite de resgates (sem race condition entre requisições).
        consumed = db.execute(
            update(Coupon)
            .where(
                Coupon.id == coupon.id,
                Coupon.active.is_(True),
                (Coupon.max_redemptions.is_(None))
                | (Coupon.redemptions_count < Coupon.max_redemptions),
            )
            .values(redemptions_count=Coupon.redemptions_count + 1)
        )
        if consumed.rowcount != 1:
            log("exhausted")
            raise INVALID_COUPON

        # 4) Aplica o desconto e registra o resgate (UNIQUE impede resgate duplicado).
        previous = sub.monthly_price
        new_price = compute_price(sub.list_price, coupon.discount_type, coupon.discount_value)
        sub.monthly_price = new_price
        sub.coupon_id = coupon.id
        db.add(
            CouponRedemption(
                coupon_id=coupon.id, company_id=user.company_id, subscription_id=sub.id,
                redeemed_by=user.id, redeemed_at=now,
                price_before=previous, price_after=new_price,
            )
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        log("duplicate")
        raise HTTPException(status.HTTP_409_CONFLICT, "Este cupom já foi utilizado pela empresa.")
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        audit_log.exception("coupon_redeem unexpected error user=%s", user.id)
        # A05: nenhuma informação interna é exposta ao cliente.
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Erro interno.")

    log("success", coupon_id=coupon.id, price_before=str(previous), price_after=str(new_price))
    return RedeemResponse(
        currency=sub.currency,
        previous_monthly_price=previous,
        discount_amount=(previous - new_price).quantize(CENT),
        new_monthly_price=new_price,
    )