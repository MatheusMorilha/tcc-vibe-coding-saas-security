import os
import re
from typing import Annotated, Optional
from datetime import datetime, timezone

from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, ForeignKey, select
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# ==========================================
# Configurações de Banco de Dados e Segurança
# ==========================================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./saas_app.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# OWASP A02:2021 - Cryptographic Failures: Uso de Argon2id para hashing seguro de senhas
ph = PasswordHasher()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==========================================
# Modelos de Banco de Dados (ORM)
# ==========================================

class Company(Base):
    __tablename__ = "companies"

    id = Column(String, primary_str=True, primary_key=True)
    name = Column(String, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    tenant_id = Column(String, ForeignKey("companies.id"), nullable=False, index=True)  # OWASP A01: Tenant Isolation
    name = Column(String(100), nullable=False)
    email = Column(String(255), nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

Base.metadata.create_all(bind=engine)

# ==========================================
# Contexto do Tenant Autenticado (Injeção de Dependência)
# ==========================================

class TenantContext(BaseModel):
    tenant_id: str
    user_id: str

def get_current_tenant_context() -> TenantContext:
    """
    OWASP A01: Broken Access Control.
    Em produção, este contexto deve ser extraído e validado do JWT/Sessão do usuário autenticado.
    Instanciado manualmente para fins deste exemplo.
    """
    return TenantContext(
        tenant_id="empresa-uuid-123",
        user_id="admin-user-uuid"
    )

# ==========================================
# Schemas de Entrada e Saída (Pydantic DTOs)
# ==========================================

class UserCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, description="Nome do usuário")
    email: EmailStr = Field(..., description="E-mail válido e único no tenant")
    password: str = Field(..., min_length=12, max_length=128, description="Senha forte")

    @field_validator("name")
    @classmethod
    def sanitize_name(cls, value: str) -> str:
        # OWASP A03: Injection / XSS - Normalização e limpeza de espaços
        cleaned = value.strip()
        if re.search(r"[<>]", cleaned):
            raise ValueError("O nome contém caracteres inválidos.")
        return cleaned

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, value: str) -> str:
        # OWASP A07: Identification and Authentication Failures - Requisitos de complexidade
        if not re.search(r"[A-Z]", value):
            raise ValueError("A senha deve conter pelo menos uma letra maiúscula.")
        if not re.search(r"[a-z]", value):
            raise ValueError("A senha deve conter pelo menos uma letra minúscula.")
        if not re.search(r"\d", value):
            raise ValueError("A senha deve conter pelo menos um número.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", value):
            raise ValueError("A senha deve conter pelo menos um caractere especial.")
        return value

class UserResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    email: EmailStr
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

# ==========================================
# Endpoints da API
# ==========================================

app = FastAPI(title="SaaS Multi-tenant User Service")

import uuid

@app.post(
    "/api/v1/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastra um novo usuário para o tenant autenticado")
def create_user(
    payload: UserCreateRequest,
    db: Session = Depends(get_db),
    tenant_ctx: TenantContext = Depends(get_current_tenant_context)):
    # OWASP A01: Broken Access Control - Garantir que o email seja único DENTRO do tenant
    existing_user = db.execute(
        select(User).where(
            User.tenant_id == tenant_ctx.tenant_id,
            User.email == payload.email.lower()
        )
    ).scalar_one_or_none()

    if existing_user:
        # OWASP A04: Insecure Design - Mensagem clara, sem vazar contexto de outros tenants
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Já existe um usuário cadastrado com este e-mail no tenant atual."
        )

    # OWASP A02: Cryptographic Failures - Hash da senha utilizando Argon2id
    hashed_password = ph.hash(payload.password)

    new_user = User(
        id=str(uuid.uuid4()),
        tenant_id=tenant_ctx.tenant_id,  # Vínculo estrito com a empresa do usuário logado
        name=payload.name,
        email=payload.email.lower(),
        password_hash=hashed_password,
        is_active=True
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user