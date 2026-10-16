"""
POST /api/v1/subscription/coupon/redeem

Resgata um cupom promocional para a assinatura da empresa do usuário autenticado
e retorna o novo valor da mensalidade.

Dependências: fastapi, pydantic>=2, sqlalchemy>=2, pyjwt, redis
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import jwt
import redis
from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import (
    CheckConstraint, DateTime, ForeignKey, Integer, String, Boolean,
    UniqueConstraint, or_, select, update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("billing.audit")
router = APIRouter(prefix="/api/v1/subscription/coupon", tags=["billing"])

# --------------------------------------------------------------------------
# Configuração (segredos SEMPRE via ambiente/secret manager, nunca no código)
# --------------------------------------------------------------------------
JWT_PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]
JWT_ISSUER = os.environ["JWT_ISSUER"]
JWT_AUDIENCE = os.environ["JWT_AUDIENCE"]
JWT_ALGORITHMS = ["RS256"]            # lista fixa: impede "alg=none" e confusão HS/RS
REDEEM_MAX_ATTEMPTS = 10              # tentativas por janela
REDEEM_WINDOW_SECONDS = 60
redis_client = redis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)

GENERIC_COUPON_ERROR = "Cupom inválido ou indisponível."


# --------------------------------------------------------------------------
# Modelos (valores monetários em centavos, inteiros: sem erros de ponto flutuante)
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    company_id: Mapped[uuid.UUID] = mapped_column(index=True)
    role: Mapped[str] = mapped_column(String(32))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class Coupon(Base):
    """Cupom é recurso da plataforma (global), não de um tenant."""
    __tablename__ = "coupons"
    __table_args__ = (
        CheckConstraint("value > 0", name="ck_coupon_value_pos"),
        CheckConstraint("discount_type IN ('percent','fixed')", name="ck_coupon_type"),
        CheckConstraint("discount_type <> 'percent' OR value <= 100", name="ck_coupon_pct"),
        CheckConstraint(
            "max_redemptions IS NULL OR redemptions_count <= max_redemptions",
            name="ck_coupon_not_oversold",
        ),
    )
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(32), unique=True)
    discount_type: Mapped[str] = mapped_column(String(8))     # percent | fixed
    value: Mapped[int] = mapped_column(Integer)               # % inteiro ou centavos
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    max_redemptions: Mapped[int | None] = mapped_column(Integer, nullable=True)
    redemptions_count: Mapped[int] = mapped_column(Integer, default=0)
    eligible_plan_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)  # None = todos


class Subscription(Base):
    __tablename__ = "subscriptions"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    company_id: Mapped[uuid.UUID] = mapped_column(index=True)  # chave de tenant
    plan_id: Mapped[uuid.UUID] = mapped_column()
    status: Mapped[str] = mapped_column(String(16))
    base_price_cents: Mapped[int] = mapped_column(Integer)     # preço de tabela do plano
    discount_cents: Mapped[int] = mapped_column(Integer, default=0)
    currency: Mapped[str] = mapped_column(String(3), default="BRL")
    coupon_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("coupons.id"), nullable=True)


class CouponRedemption(Base):
    __tablename__ = "coupon_redemptions"
    # Uma empresa só pode usar o mesmo cupom uma vez (garantido pelo banco).
    __table_args__ = (UniqueConstraint("coupon_id", "company_id", name="uq_coupon_company"),)
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    coupon_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("coupons.id"))
    company_id: Mapped[uuid.UUID] = mapped_column(index=True)
    user_id: Mapped[uuid.UUID] = mapped_column()
    discount_cents: Mapped[int] = mapped_column(Integer)
    redeemed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------
_CODE_RE = re.compile(r"^[A-Z0-9-]{4,32}$")


class RedeemRequest(BaseModel):
    # extra="forbid": rejeita campos inesperados (ex.: company_id, price, discount)
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    code: str = Field(min_length=4, max_length=32)

    @field_validator("code")
    @classmethod
    def normalize(cls, v: str) -> str:
        v = v.upper()
        if not _CODE_RE.fullmatch(v):
            raise ValueError("formato inválido")
        return v


class RedeemResponse(BaseModel):
    previous_monthly_price_cents: int
    discount_cents: int
    new_monthly_price_cents: int
    currency: str


# --------------------------------------------------------------------------
# Dependências: sessão, autenticação, autorização, rate limit
# --------------------------------------------------------------------------
def get_db():  # fornecido pela aplicação (SessionLocal) – exemplo:
    from app.database import SessionLocal  # noqa
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    company_id: uuid.UUID
    role: str


def get_principal(
    authorization: str = Header(default=""), db: Session = Depends(get_db)
) -> Principal:
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "Não autenticado.",
                                 headers={"WWW-Authenticate": "Bearer"})
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise unauthorized
    try:
        claims = jwt.decode(
            token, JWT_PUBLIC_KEY, algorithms=JWT_ALGORITHMS,
            audience=JWT_AUDIENCE, issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "sub"]},
        )
        user_id = uuid.UUID(claims["sub"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise unauthorized

    # Fonte da verdade do tenant e do papel é o BANCO, não o corpo da requisição
    # (e permite revogação imediata de usuários desativados).
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise unauthorized
    return Principal(user.id, user.company_id, user.role)


def require_billing_admin(p: Principal = Depends(get_principal)) -> Principal:
    if p.role not in {"owner", "billing_admin"}:      # RBAC: negar por padrão
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente.")
    return p


def redeem_rate_limit(p: Principal = Depends(require_billing_admin)) -> None:
    """Dificulta enumeração/força bruta de códigos de cupom."""
    key = f"rl:coupon:{p.company_id}:{p.user_id}"
    try:
        n = redis_client.incr(key)
        if n == 1:
            redis_client.expire(key, REDEEM_WINDOW_SECONDS)
    except redis.RedisError:
        # Falha fechada: sem limitador, não aceitamos tentativas de adivinhação.
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Tente novamente em instantes.")
    if n > REDEEM_MAX_ATTEMPTS:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Muitas tentativas.",
                            headers={"Retry-After": str(REDEEM_WINDOW_SECONDS)})


# --------------------------------------------------------------------------
# Regras de preço (100% no servidor)
# --------------------------------------------------------------------------
def compute_discount_cents(coupon: Coupon, base_price_cents: int) -> int:
    if coupon.discount_type == "percent":
        discount = base_price_cents * coupon.value // 100   # aritmética inteira
    else:
        discount = coupon.value
    return max(0, min(discount, base_price_cents))           # nunca fica negativo


def _code_fingerprint(code: str) -> str:
    """Identificador para logs sem expor o código completo."""
    return hashlib.sha256(code.encode()).hexdigest()[:12]


# --------------------------------------------------------------------------
# Rota
# --------------------------------------------------------------------------
@router.post("/redeem", response_model=RedeemResponse)
def redeem_coupon(
    body: RedeemRequest,
    response: Response,
    principal: Principal = Depends(redeem_rate_limit),
    db: Session = Depends(get_db),
) -> RedeemResponse:
    response.headers["Cache-Control"] = "no-store"
    now = datetime.now(timezone.utc)
    fp = _code_fingerprint(body.code)

    def fail(reason: str, http_status: int, detail: str):
        db.rollback()
        logger.warning("coupon_redeem_denied", extra={
            "company_id": str(principal.company_id), "user_id": str(principal.user_id),
            "code_fp": fp, "reason": reason})
        raise HTTPException(http_status, detail)

    try:
        # 1) Assinatura da empresa do token, com lock de linha: serializa
        #    resgates concorrentes da mesma empresa (anti race condition).
        sub = db.execute(
            select(Subscription)
            .where(Subscription.company_id == principal.company_id,   # isolamento de tenant
                   Subscription.status == "active")
            .with_for_update()
        ).scalar_one_or_none()
        if sub is None:
            fail("no_active_subscription", status.HTTP_409_CONFLICT,
                 "Nenhuma assinatura ativa encontrada.")
        if sub.coupon_id is not None:
            fail("coupon_already_applied", status.HTTP_409_CONFLICT,
                 "A assinatura já possui um cupom aplicado.")

        # 2) Busca do cupom (ORM parametrizado, sem SQL concatenado)
        coupon = db.execute(
            select(Coupon).where(
                Coupon.code == body.code,
                Coupon.active.is_(True),
                Coupon.valid_from <= now,
                Coupon.valid_until > now,
            )
        ).scalar_one_or_none()
        # Mesma resposta para inexistente/expirado/inelegível: evita enumeração.
        if coupon is None or (
            coupon.eligible_plan_id is not None and coupon.eligible_plan_id != sub.plan_id
        ):
            fail("invalid_or_ineligible", status.HTTP_422_UNPROCESSABLE_ENTITY,
                 GENERIC_COUPON_ERROR)

        # 3) Reserva atômica de uso: UPDATE condicional impede estourar o limite
        claimed = db.execute(
            update(Coupon)
            .where(Coupon.id == coupon.id,
                   or_(Coupon.max_redemptions.is_(None),
                       Coupon.redemptions_count < Coupon.max_redemptions))
            .values(redemptions_count=Coupon.redemptions_count + 1)
        )
        if claimed.rowcount != 1:
            fail("exhausted", status.HTTP_422_UNPROCESSABLE_ENTITY, GENERIC_COUPON_ERROR)

        # 4) Preço calculado no servidor, a partir do preço de tabela do plano
        discount = compute_discount_cents(coupon, sub.base_price_cents)

        db.add(CouponRedemption(
            id=uuid.uuid4(), coupon_id=coupon.id, company_id=principal.company_id,
            user_id=principal.user_id, discount_cents=discount, redeemed_at=now))
        sub.coupon_id = coupon.id
        sub.discount_cents = discount
        db.flush()           # dispara a UNIQUE (coupon_id, company_id), se violada
        db.commit()

    except IntegrityError:
        fail("already_redeemed_by_company", status.HTTP_422_UNPROCESSABLE_ENTITY,
             GENERIC_COUPON_ERROR)
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        logger.exception("coupon_redeem_error", extra={
            "company_id": str(principal.company_id), "code_fp": fp})
        # Nunca vaza stack trace nem detalhes internos ao cliente
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Erro interno.")

    logger.info("coupon_redeemed", extra={
        "company_id": str(principal.company_id), "user_id": str(principal.user_id),
        "coupon_id": str(coupon.id), "code_fp": fp, "discount_cents": discount})

    return RedeemResponse(
        previous_monthly_price_cents=sub.base_price_cents,
        discount_cents=discount,
        new_monthly_price_cents=sub.base_price_cents - discount,
        currency=sub.currency,
    )