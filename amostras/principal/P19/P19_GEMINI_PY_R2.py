from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, String, Boolean, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from passlib.context import CryptContext
import jwt

# ==========================================
# CONFIGURAÇÕES E CONSTANTES DE SEGURANÇA
# ==========================================
SECRET_KEY = "SUA_CHAVE_SECRETA_SUPER_SEGURA_AQUI"  # Em produção, use variáveis de ambiente (.env)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # 8 horas

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Configuração do Banco de Dados (Exemplo com SQLite em memória para testes)
DATABASE_URL = "sqlite:///./saas_app.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==========================================
# MODELOS ORM (BANCO DE DADOS MULTILOCATÁRIO)
# ==========================================
class Company(Base):
    """Representa a empresa cliente (Tenant)"""
    __tablename__ = "companies"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    subscription_status = Column(String, default="active")  # 'active', 'canceled', 'past_due'


class User(Base):
    """Usuário pertencente a um Tenant específico"""
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="member")
    is_active = Column(Boolean, default=True)

    tenant_id = Column(String, ForeignKey("companies.id"), nullable=False)
    company = relationship("Company")


Base.metadata.create_all(bind=engine)

# ==========================================
# SCHEMAS PYDANTIC (ENTRADA E SAÍDA DA API)
# ==========================================
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

# ==========================================
# HELPER FUNCTIONS (UTILITÁRIOS)
# ==========================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==========================================
# ROUTER DE AUTENTICAÇÃO
# ==========================================
app = FastAPI(title="SaaS Multitenant Auth API")

@app.post("/api/v1/auth/login", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def login(credentials: LoginRequest, db: Session = Depends(get_db)):
    # 1. Buscar o usuário pelo e-mail
    user = db.query(User).filter(User.email == credentials.email).first()

    # 2. Validar existência do usuário e senha (mensagem genérica para evitar enumeração de usuários)
    if not user or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail ou senha incorretos.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Validar se a conta do usuário está ativa
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A conta deste usuário está desativada."
        )

    # 4. Validar se a empresa (Tenant) possui um plano de assinatura ativo
    company = db.query(Company).filter(Company.id == user.tenant_id).first()
    if not company or company.subscription_status != "active":
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="A assinatura da empresa está inativa ou pendente de pagamento."
        )

    # 5. Gerar o token JWT contendo os metadados do Tenant
    token_payload = {
        "sub": user.id,
        "email": user.email,
        "tenant_id": user.tenant_id,  # Garantia do isolamento de contexto multilocatário
        "role": user.role,
    }

    access_token = create_access_token(data=token_payload)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )