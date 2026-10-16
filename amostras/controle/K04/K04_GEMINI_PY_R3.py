import logging
from typing import Generator
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field, validator
from passlib.context import CryptContext
from sqlalchemy import Column, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# ------------------------------------------------------------------------------
# Setup de Segurança e Logs (OWASP A02 & A09)
# ------------------------------------------------------------------------------
logger = logging.getLogger("saas_app.security")

# Argon2id é a recomendação principal do OWASP para Hashing de Senhas
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


# ------------------------------------------------------------------------------
# Configuração do Banco de Dados (SQLAlchemy - OWASP A03)
# ------------------------------------------------------------------------------
DATABASE_URL = "sqlite:///./saas_multitenant.db"  # Substituir por PostgreSQL/MySQL
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class UserModel(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, index=True)  # Chave do Locatário
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ------------------------------------------------------------------------------
# Dependência de Autenticação / Tenant Context (OWASP A01)
# ------------------------------------------------------------------------------
def get_current_tenant_id() -> str:
    """
    Simulação de extração do Tenant ID a partir do Token JWT de quem faz a requisição.
    Em produção, decodifique o cabeçalho Authorization (Bearer token).
    """
    # Exemplo: retornado do payload validado do JWT
    return "company_tenant_xyz123"


# ------------------------------------------------------------------------------
# Schemas de Entrada e Saída (Pydantic - OWASP A04 & Input Validation)
# ------------------------------------------------------------------------------
class UserCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=10, max_length=128)

    @validator("password")
    def validate_password_complexity(cls, value: str) -> str:
        """Valida força da senha conforme diretrizes OWASP (A04)."""
        if not any(char.isdigit() for char in value):
            raise ValueError("A senha deve conter pelo menos um número.")
        if not any(char.isupper() for char in value):
            raise ValueError("A senha deve conter pelo menos uma letra maiúscula.")
        if not any(char.islower() for char in value):
            raise ValueError("A senha deve conter pelo menos uma letra minúscula.")
        if not any(char in "!@#$%^&*()_+-=[]{}|;:,.<>?" for char in value):
            raise ValueError("A senha deve conter pelo menos um caractere especial.")
        return value


class UserResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    email: EmailStr

    class Config:
        from_attributes = True


# ------------------------------------------------------------------------------
# Rota da API (FastAPI Router)
# ------------------------------------------------------------------------------
router = APIRouter(prefix="/users", tags=["Users"])


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastra um novo usuário no locatário atual",)
def create_user(
    payload: UserCreateRequest,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant_id),):
    # 1. Tratar e sanitizar e-mail
    clean_email = payload.email.lower().strip()

    # 2. Verificar se o e-mail já está cadastrado DENTRO DO MESMO LOCATÁRIO
    existing_user = db.execute(
        select(UserModel).where(
            UserModel.tenant_id == tenant_id,
            UserModel.email == clean_email
        )
    ).scalar_one_or_none()

    if existing_user:
        logger.warning(
            f"Tentativa de cadastro com e-mail duplicado no tenant [{tenant_id}]: {clean_email}"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Já existe um usuário cadastrado com este e-mail nesta empresa.",
        )

    # 3. Gerar hash seguro da senha (Argon2id)
    hashed_pwd = hash_password(payload.password)

    # 4. Instanciar e persistir o novo usuário
    import uuid
    new_user = UserModel(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        name=payload.name.strip(),
        email=clean_email,
        hashed_password=hashed_pwd,
    )

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        logger.info(f"Usuário [{new_user.id}] cadastrado com sucesso no tenant [{tenant_id}].")
    except Exception as exc:
        db.rollback()
        logger.error(f"Erro ao persistir usuário no banco: {str(exc)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao processar o cadastro.",
        )

    # 5. Retornar resposta formatada sem expor a senha
    return new_user