from datetime import datetime
from enum import Enum
from typing import List, Optional
from fastapi import FastAPI, Depends, Query, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict
from sqlalchemy import create_engine, Column, String, DateTime, ForeignKey, Integer, func, or_, select
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# ------------------------------------------------------------------------------
# 1. Configuração do Banco de Dados & ORM
# ------------------------------------------------------------------------------
DATABASE_URL = "postgresql://user:password@localhost:5432/saas_db"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class DocumentType(str, Enum):
    CONTRACT = "CONTRACT"
    INVOICE = "INVOICE"
    REPORT = "REPORT"
    OTHER = "OTHER"


class Document(Base):
    __tablename__ = "documents"

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, index=True)  # Chave deAqui está a implementação de uma rota de busca textual em documentos desenvolvida em **Python** utilizando **FastAPI** e **SQLAlchemy**.

from datetime import date
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Date, ForeignKey, Integer, func, or_
from sqlalchemy.orm import Session, declarative_base
from sqlalchemy.dialects.postgresql import TSVECTOR

# --- MODELS & SCHEMAS ---

Base = declarative_base()

class DocumentModel(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, nullable=False, index=True)  # Isolamento Multilocatário
    title = Column(String, nullable=False)
    content = Column(String, nullable=False)
    doc_type = Column(String, nullable=False)
    author_id = Column(Integer, nullable=False)
    created_at = Column(Date, nullable=False)

    # Campo tsvector mantido pelo PostgreSQL para busca textual rápida
    search_vector = Column(TSVECTOR)


class DocumentResponse(BaseModel):
    id: int
    title: str
    doc_type: str
    author_id: int
    created_at: date

    class Config:
        from_attributes = True


class PaginatedDocumentResponse(BaseModel):
    total: int
    page: int
    page_size: int
    data: List[DocumentResponse]


class TenantContext(BaseModel):
    tenant_id: int
    user_id: int


# --- DEPENDÊNCIES DE CONTEXTO E BANCO ---

def get_db():
    """Dependency para injeção da sessão do banco de dados."""
    db = Session()
    try:
        yield db
    finally:
        db.close()


def get_current_tenant() -> TenantContext:
    """
    Simula a extração do tenant_id a partir do Token JWT do usuário autenticado.
    Garante o isolamento dos dados antes de qualquer execução de query.
    """
    # Exemplo retornado após validação do JWT no middleware/auth
    return TenantContext(tenant_id=101, user_id=45)


# --- ROUTER ---

router = APIRouter(prefix="/api/v1/documents", tags=["Documents"])


@router.get("/search", response_model=PaginatedDocumentResponse)
def search_documents(
    q: Optional[str] = Query(None, description="Termo de busca textual"),
    doc_type: Optional[str] = Query(None, description="Filtrar por tipo do documento (ex: pdf, contrato)"),
    author_id: Optional[int] = Query(None, description="Filtrar por ID do autor"),
    start_date: Optional[date] = Query(None, description="Data inicial do intervalo (YYYY-MM-DD)"),
    end_date: Optional[date] = Query(None, description="Data final do intervalo (YYYY-MM-DD)"),
    page: int = Query(1, ge=1, description="Número da página"),
    page_size: int = Query(20, ge=1, le=100, description="Itens por página"),
    tenant: TenantContext = Depends(get_current_tenant),
    db: Session = Depends(get_db)):
    """
    Realiza busca de documentos aplicando isolamento de tenant e filtros dinâmicos combináveis.
    """
    # 1. VALIDAÇÃO DE SEGURANÇA E REGRAS
    if start_date and end_date and start_date > end_date:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A data inicial (start_date) não pode ser posterior à data final (end_date)."
        )

    # 2. ISOLAMENTO MULTILOCATÁRIO (OBRIGATÓRIO)
    # Toda consulta começa explicitamente travada no tenant do usuário autenticado
    query = db.query(DocumentModel).filter(DocumentModel.tenant_id == tenant.tenant_id)

    # 3. FILTRO TEXTUAL (PostgreSQL Full-Text Search com fallback para ILIKE)
    if q and q.strip():
        search_term = q.strip()
        # Converte a query para tsquery (suporta busca por radicais/termos em português)
        ts_query = func.plainto_tsquery('portuguese', search_term)

        # Filtra pelo TSVECTOR indexado ou faz fallback no título com ILIKE
        query = query.filter(
            or_(
                DocumentModel.search_vector.op("@@")(ts_query),
                DocumentModel.title.ilike(f"%{search_term}%")
            )
        )

    # 4. FILTROS OPCIONAIS COMBINÁVEIS
    if doc_type:
        query = query.filter(DocumentModel.doc_type == doc_type.lower())

    if author_id:
        query = query.filter(DocumentModel.author_id == author_id)

    if start_date:
        query = query.filter(DocumentModel.created_at >= start_date)

    if end_date:
        query = query.filter(DocumentModel.created_at <= end_date)

    # 5. CONTAGEM E PAGINAÇÃO
    total = query.count()

    offset = (page - 1) * page_size
    results = query.order_by(DocumentModel.created_at.desc())\
                   .offset(offset)\
                   .limit(page_size)\
                   .all()

    return PaginatedDocumentResponse(
        total=total,
        page=page,
        page_size=page_size,
        data=results
    )