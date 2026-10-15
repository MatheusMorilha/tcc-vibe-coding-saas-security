import os
import re
from typing import Generator
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from sqlalchemy import Column, Integer, String, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship

# ==============================================================================
# CONFIGURAÇÃO DE SEGURANÇA E BANCO DE DADOS
# ==============================================================================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==============================================================================
# MODELOS DE DADOS (ORM - SQLAlchemy)
# ==============================================================================

class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    subscription_status = Column(String(50), default="active")

    users = relationship("User", back_populates="company")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("companies.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)

    company = relationship("Company", back_populates="users")


# ==============================================================================
# SCHEMAS DE VALIDAÇÃO (Pydantic)
# ==============================================================================

class UserCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, example="João Silva")
    email: EmailStr = Field(..., example="joao.silva@empresa.com")
    password: str = Field(..., min_length=8, max_length=128, example="Senha@Segura123")

    @classmethod
    def validate_password_strength(cls, password: str) -> str:
        if not re.search(r"[A-Z]", password):
            raise ValueError("A senha deve conter pelo menos uma letra maiúscula.")
        if not re.search(r"[a-z]", password):
            raise ValueError("A senha deve conter pelo menos uma letra minúscula.")
        if not re.search(r"\d", password):
            raise ValueError("A senha deve conter pelo menos um número.")
        return password


class UserResponse(BaseModel):
    id: int
    tenant_id: int
    name: str
    email: EmailStr

    class Config:
        from_attributes = True


# ==============================================================================
# DEPENDÊNCIA DE MULTITENANCY E ROTAS DA API
# ==============================================================================

def get_current_tenant_id() -> int:
    """
    Em produção, extrai o tenant_id do token JWT do usuário autenticado
    ou do header HTTP da requisição (ex: 'X-Tenant-ID').
    """
    # Exemplo mockado do ID da empresa requisitante
    return 1


router = APIRouter(prefix="/users", tags=["Users"])


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastra um novo usuário no tenant atual")
def create_user(
    payload: UserCreateRequest,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id)):
    # 1. Validação simples de complexidade da senha
    UserCreateRequest.validate_password_strength(payload.password)

    # 2. Garante isolamento: o e-mail deve ser único dentro do mesmo tenant
    existing_user = db.query(User).filter(
        User.tenant_id == tenant_id,
        User.email == payload.email
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Já existe um usuário cadastrado com este e-mail nesta empresa."
        )

    # 3. Hash seguro da senha
    hashed_pwd = pwd_context.hash(payload.password)

    # 4. Instanciação do modelo garantindo a associação com o tenant_id
    new_user = User(
        tenant_id=tenant_id,
        name=payload.name,
        email=payload.email,
        hashed_password=hashed_pwd
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user