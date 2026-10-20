from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Boolean, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# Configuração do Banco de Dados (Exemplo com SQLite/PostgreSQL)
SQLALCHEMY_DATABASE_URL = "sqlite:///./saas_platform.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modelo SQLAlchemy para a tabela de Clientes (Tenants)
class ClientModel(Base):
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    subdomain = Column(String, unique=True, index=True, nullable=False)
    plan = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)

# Esquema Pydantic para Serialização da Resposta
class ClientResponse(BaseModel):
    id: int
    name: str
    subdomain: str
    plan: str
    is_active: bool

    class Config:
        from_attributes = True

app = FastAPI(title="SaaS Management API", version="1.0.0")

# Dependência para obter a sessão do banco de dados
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Rota de API para listar e filtrar clientes
@app.get("/api/v1/clients", response_model=List[ClientResponse], summary="Listar e filtrar clientes cadastrados")
def list_clients(
    name: Optional[str] = Query(None, description="Filtrar clientes pelo nome (busca parcial)"),
    skip: int = Query(0, ge=0, description="Número de registros para pular (paginação)"),
    limit: int = Query(50, ge=1, le=100, description="Número máximo de registros retornados"),
    db: Session = Depends(get_db)
):
    query = db.query(ClientModel)

    # Aplica o filtro por nome caso seja fornecido na requisição
    if name:
        query = query.filter(ClientModel.name.ilike(f"%{name}%"))

    clients = query.offset(skip).limit(limit).all()
    return clients