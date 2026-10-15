from datetime import datetime
from typing import Optional

import jwt  # PyJWT
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import DateTime, ForeignKey, Integer, String, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Toda tabela de dados de negócio carrega o tenant (empresa) dono do registro.
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CustomerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    email: Optional[str] = None
    created_at: datetime


class CustomerListOut(BaseModel):
    items: list[CustomerOut]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# Dependências (sessão de banco e autenticação)
# ---------------------------------------------------------------------------

JWT_SECRET = "troque-por-segredo-vindo-de-variavel-de-ambiente"
JWT_ALGORITHM = "HS256"


class CurrentUser(BaseModel):
    id: int
    tenant_id: int


def get_db():
    """Substitua pela sua fábrica de sessões (SessionLocal)."""
    from app.database import SessionLocal  # ajuste ao seu projeto

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(authorization: str = Header(...)) -> CurrentUser:
    """
    Valida o token e extrai o usuário e o tenant_id das claims assinadas.
    O tenant NUNCA é lido de query string, body ou headers controlados pelo cliente.
    """
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciais inválidas.")

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return CurrentUser(id=int(payload["sub"]), tenant_id=int(payload["tenant_id"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido ou expirado.")


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/customers", tags=["Clientes"])


def _escape_like(term: str) -> str:
    """Escapa curingas do LIKE para que o termo seja tratado como texto literal."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("", response_model=CustomerListOut)
def list_customers(
    name: Optional[str] = Query(
        None, min_length=1, max_length=100, description="Filtra por nome (contém)."
    ),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Filtro de tenant obrigatório: vem do usuário autenticado.
    filters = [Customer.tenant_id == user.tenant_id]

    if name and name.strip():
        pattern = f"%{_escape_like(name.strip())}%"
        filters.append(Customer.name.ilike(pattern, escape="\\"))

    total = db.scalar(select(func.count()).select_from(Customer).where(*filters)) or 0

    customers = db.scalars(
        select(Customer)
        .where(*filters)
        .order_by(Customer.name, Customer.id)  # id desempata, garantindo paginação estável
        .limit(limit)
        .offset(offset)
    ).all()

    return CustomerListOut(
        items=[CustomerOut.model_validate(c) for c in customers],
        total=total,
        limit=limit,
        offset=offset,
    )