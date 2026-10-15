from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, ConfigDict
from sqlalchemy import Column, String, Integer, ForeignKey, create_engine, select
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from passlib.context import CryptContext
from typing import Annotated

# ------------------------------------------------------------------------------
# Configuração de Segurança e Hashing
# ------------------------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# ------------------------------------------------------------------------------
# Configuração do Banco de Dados (ORM)
# ------------------------------------------------------------------------------
Base = declarative_base()

class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, nullable=False, index=True)  # Chave de isolamento multilocatário
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)

# Banco SQLite em memória para fins demonstrativos
DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------------------------------------------------------------------
# Schemas (Pydantic)
# ------------------------------------------------------------------------------
class UserCreateRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    tenant_id: int
    name: str
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)

# ------------------------------------------------------------------------------
# Injeção do Tenant Atual (Contexto do Multitenancy)
# ------------------------------------------------------------------------------
def get_current_tenant_id() -> int:
    """
    Simulação da extração do tenant_id a partir do Token JWT do usuário autenticado.
    Em produção, este valor vem de `request.state` ou decodificação do JWT Bearer token.
    """
    return 101  # Exemplo: Empresa/Tenant ID = 101

# ------------------------------------------------------------------------------
# Aplicação FastAPI e Rota
# ------------------------------------------------------------------------------
app = FastAPI(title="SaaS Multi-Tenant API")

@app.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastra um novo usuário no tenant autenticado")
def create_user(
    payload: UserCreateRequest,
    db: Annotated[Session, Depends(get_db)],
    current_tenant_id: Annotated[int, Depends(get_current_tenant_id)]):
    # 1. Validação de Unicidade de E-mail DENTRO do Tenant
    existing_user_stmt = select(UserModel).where(
        UserModel.tenant_id == current_tenant_id,
        UserModel.email == payload.email
    )
    existing_user = db.execute(existing_user_stmt).scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Já existe um usuário cadastrado com este e-mail nesta empresa."
        )

    # 2. Hashing seguro da senha antes da persistência
    hashed_pwd = hash_password(payload.password)

    # 3. Instanciação e Vínculo Obrigatório ao tenant_id
    new_user = UserModel(
        tenant_id=current_tenant_id,
        name=payload.name,
        email=payload.email,
        hashed_password=hashed_pwd
    )

    # 4. Transação no banco de dados
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user