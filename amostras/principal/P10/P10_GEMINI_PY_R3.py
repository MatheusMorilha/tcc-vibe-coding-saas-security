import os
import uuid
from typing import Generator, Optional
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, status, Header
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# ------------------------------------------------------------------------------
# Configuration & Security Setup
# ------------------------------------------------------------------------------

pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# Database Setup (Exemplo com SQLite em memória/PostgreSQL)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ------------------------------------------------------------------------------
# Database Model
# ------------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Garante que o e-mail seja único dentro de cada empresa (tenant)
    __table_args__ = (
        UniqueConstraint('tenant_id', 'email', name='uix_tenant_email'),
    )

Base.metadata.create_all(bind=engine)

# ------------------------------------------------------------------------------
# Pydantic Schemas (DTOs)
# ------------------------------------------------------------------------------

class UserCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, example="João Silva")
    email: EmailStr = Field(..., example="joao.silva@empresa.com")
    password: str = Field(..., min_length=8, max_length=128, example="SenhaSegura123!")

class UserResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    email: EmailStr
    created_at: datetime

    class Config:
        from_attributes = True

# ------------------------------------------------------------------------------
# Dependencies & Middleware Helpers
# ------------------------------------------------------------------------------

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_tenant_id(
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID")) -> str:
    """
    Resolve o contexto do Tenant. Em produção, este valor deve ser extraído
    do Payload do JWT autenticado (claims do usuário logado) ou via middleware.
    """
    if not x_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Header 'X-Tenant-ID' é obrigatório para identificação do locatário."
        )
    return x_tenant_id

# ------------------------------------------------------------------------------
# API Route Implementation
# ------------------------------------------------------------------------------

app = FastAPI(title="SaaS Multi-tenant User Management API")

@app.post(
    "/api/v1/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastra um novo usuário na empresa (Tenant)")
def create_user(
    payload: UserCreateRequest,
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db)):
    # 1. Normalização dos dados de entrada
    email_normalized = payload.email.lower().strip()

    # 2. Verifica se o e-mail já existe dentro deste Tenant específico
    existing_user = db.query(User).filter(
        User.tenant_id == tenant_id,
        User.email == email_normalized
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Já existe um usuário cadastrado com este e-mail nesta empresa."
        )

    # 3. Hash seguro da senha
    hashed_pwd = get_password_hash(payload.password)

    # 4. Instanciação e persistência com isolamento de tenant
    new_user = User(
        tenant_id=tenant_id,
        name=payload.name.strip(),
        email=email_normalized,
        hashed_password=hashed_pwd
    )

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except Exception as err:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao persistir o registro no banco de dados."
        ) from err

    # 5. Retorno sanitizado via Pydantic Schema (omite hashed_password)
    return new_user