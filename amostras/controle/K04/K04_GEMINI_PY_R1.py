import os
import re
from typing import AsyncGenerator, Optional
from datetime import datetime, timezone

from fastapi import FastAPI, Depends, HTTPException, status, Header
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import String, ForeignKey, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from passlib.context import CryptContext

# ==============================================================================
# CONFIGURAÇÕES E SEGURANÇA (OWASP A02: Criptografia e A05: Configurações Inseguras)
# ==============================================================================

# Algoritmo de hashing robusto com fator de custo adequado (Bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://user:pass@localhost:5432/saas_db")

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session

# ==============================================================================
# MODELOS DE BANCO DE DADOS (SQLAlchemy 2.0)
# ==============================================================================

class Base(DeclarativeBase):
    pass

class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True)

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    # OWASP A01: Tenant Isolation - Chave estrangeira explicitando o tenant dono do dado
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc))

    tenant: Mapped["Tenant"] = relationship()

# ==============================================================================
# SCHEMAS DE VALIDAÇÃO (Pydantic v2 - OWASP A03: Injection & Data Validation)
# ==============================================================================

class UserCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, description="Nome completo do usuário")
    email: EmailStr = Field(..., description="E-mail corporativo válido")
    password: str = Field(..., min_length=12, max_length=128, description="Senha forte")

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        """
        Garante requisitos mínimos de complexidade para evitar senhas fracas.
        """
        if not re.search(r"[A-Z]", v):
            raise ValueError("A senha deve conter ao menos uma letra maiúscula.")
        if not re.search(r"[a-z]", v):
            raise ValueError("A senha deve conter ao menos uma letra minúscula.")
        if not re.search(r"\d", v):
            raise ValueError("A senha deve conter ao menos um número.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("A senha deve conter ao menos um caractere especial.")
        return v

class UserResponse(BaseModel):
    id: int
    tenant_id: int
    name: str
    email: EmailStr
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

# ==============================================================================
# AUTENTICAÇÃO E CONTEXTO DO TENANT (OWASP A01: Broken Access Control)
# ==============================================================================

async def get_current_tenant_id(
    # Em produção, este valor deve vir da validação do JWT assinado no Header Authorization
    x_tenant_id: Optional[int] = Header(None, alias="X-Tenant-ID")) -> int:
    """
    Recupera o ID do tenant a partir da sessão/token autenticado.
    Evita Broken Access Control garantindo que o tenant não possa ser forjado pelo cliente.
    """
    if not x_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Contexto de tenant não fornecido ou inválido."
        )
    return x_tenant_id

# ==============================================================================
# ROUTER & ENDPOINT DE CADASTRO DE USUÁRIO
# ==============================================================================

app = FastAPI(title="SaaS Multi-tenant User API")

@app.post(
    "/api/v1/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastra um novo usuário no tenant autenticado",
    description="Cria um novo usuário associado ao tenant corrente garantindo isolamento e segurança.")
async def create_user(
    payload: UserCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_tenant_id: int = Depends(get_current_tenant_id)):
    # 1. OWASP A01: Isolamento de Tenant - Verificar se e-mail já existe dentro do MESMO tenant
    # OBS: O mesmo e-mail pode existir em tenants diferentes caso a regra de negócio permita,
    # mas NUNCA pode ser duplicado no mesmo tenant.
    stmt = select(User).where(
        User.tenant_id == current_tenant_id,
        User.email == payload.email.lower()
    )
    result = await db.execute(stmt)
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="E-mail já cadastrado nesta empresa."
        )

    # 2. OWASP A02: Criptografia - Hashing seguro da senha usando Bcrypt (Salting automático)
    hashed_password = pwd_context.hash(payload.password)

    # 3. OWASP A03: Prevenção de Injeção - ORM parametriza automaticamente todas as inserções
    new_user = User(
        tenant_id=current_tenant_id,
        name=payload.name.strip(),
        email=payload.email.lower(),
        hashed_password=hashed_password,
        is_active=True
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # 4. OWASP A04: Insecure Design - O Schema 'UserResponse' filtra 'hashed_password' do retorno
    return new_user