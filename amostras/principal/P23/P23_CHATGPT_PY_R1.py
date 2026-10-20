
import os
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine,
    String,
    ForeignKey,
    UniqueConstraint,
    DateTime,
    JSON,
    select,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)


# --------------------------------------------------
# Configuração
# --------------------------------------------------

DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


# --------------------------------------------------
# Modelos
# --------------------------------------------------

class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True
    )
    subscription_status: Mapped[str] = mapped_column(String(30))


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True
    )
    tenant_id: Mapped[UUID] = mapped_column(
        ForeignKey("tenants.id"), index=True
    )
    active: Mapped[bool]


class Draft(Base):
    __tablename__ = "form_drafts"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True
    )
    tenant_id: Mapped[UUID] = mapped_column(
        ForeignKey("tenants.id"), index=True
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id"), index=True
    )
    form_key: Mapped[str] = mapped_column(String(100))
    data: Mapped[dict[str, Any]] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "user_id",
            "form_key",
            name="uq_draft_tenant_user_form",
        ),
    )


# --------------------------------------------------
# Sessão de banco de dados
# --------------------------------------------------

def get_db():
    with SessionLocal() as db:
        yield db


# --------------------------------------------------
# Autenticação e isolamento do tenant
# --------------------------------------------------

security = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    token = credentials.credentials

    try:
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )
        user_id = UUID(claims["sub"])
    except (JWTError, ValueError, KeyError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado",
        )

    user = db.scalar(
        select(User).where(
            User.id == user_id,
            User.active.is_(True),
        )
    )

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Usuário não encontrado ou inativo",
        )

    tenant = db.get(Tenant, user.tenant_id)

    if tenant is None:
        raise HTTPException(status_code=403, detail="Empresa inválida")

    if tenant.subscription_status != "active":
        raise HTTPException(
            status_code=403,
            detail="Assinatura da empresa não está ativa",
        )

    # O tenant é obtido do usuário autenticado.
    # Nunca confiar em tenant_id enviado pelo cliente.
    return user


# --------------------------------------------------
# Contrato da API
# --------------------------------------------------

class DraftInput(BaseModel):
    data: dict[str, Any] = Field(
        description="Objeto completo do formulário a persistir"
    )


class DraftOutput(BaseModel):
    form_key: str
    data: dict[str, Any]
    updated_at: datetime


app = FastAPI(title="API de Rascunhos SaaS")


# Em produção, prefira migrações com Alembic.
# Este comando cria as tabelas ausentes.
# Base.metadata.create_all(bind=engine)


# --------------------------------------------------
# Salvar ou atualizar um rascunho
# --------------------------------------------------

@app.put("/drafts/{form_key}", response_model=DraftOutput)
def save_draft(
    form_key: str,
    body: DraftInput,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not form_key or len(form_key) > 100:
        raise HTTPException(status_code=400, detail="Formulário inválido")

    draft = db.scalar(
        select(Draft).where(
            Draft.tenant_id == user.tenant_id,
            Draft.user_id == user.id,
            Draft.form_key == form_key,
        )
    )

    now = datetime.now(timezone.utc)

    if draft is None:
        draft = Draft(
            id=__import__("uuid").uuid4(),
            tenant_id=user.tenant_id,
            user_id=user.id,
            form_key=form_key,
            data=body.data,
            updated_at=now,
        )
        db.add(draft)
    else:
        draft.data = body.data
        draft.updated_at = now

    try:
        db.commit()
        db.refresh(draft)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Não foi possível salvar o rascunho",
        )

    return DraftOutput(
        form_key=draft.form_key,
        data=draft.data,
        updated_at=draft.updated_at,
    )


# --------------------------------------------------
# Recuperar e reconstruir o objeto salvo
# --------------------------------------------------

@app.get("/drafts/{form_key}", response_model=DraftOutput)
def restore_draft(
    form_key: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    draft = db.scalar(
        select(Draft).where(
            Draft.tenant_id == user.tenant_id,
            Draft.user_id == user.id,
            Draft.form_key == form_key,
        )
    )

    if draft is None:
        raise HTTPException(
            status_code=404,
            detail="Rascunho não encontrado",
        )

    # JSON é desserializado pelo driver e pelo SQLAlchemy
    # para um objeto Python: dict, list, str, int etc.
    restored_data = draft.data

    return DraftOutput(
        form_key=draft.form_key,
        data=restored_data,
        updated_at=draft.updated_at,
    )


# --------------------------------------------------
# Excluir um rascunho
# --------------------------------------------------

@app.delete("/drafts/{form_key}", status_code=204)
def delete_draft(
    form_key: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    draft = db.scalar(
        select(Draft).where(
            Draft.tenant_id == user.tenant_id,
            Draft.user_id == user.id,
            Draft.form_key == form_key,
        )
    )

    if draft is None:
        raise HTTPException(
            status_code=404,
            detail="Rascunho não encontrado",
        )

    db.delete(draft)
    db.commit()
