from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

# Imports hipotéticos da estrutura da sua aplicação
from app.database import get_db_session
from app.models.document import DocumentModel
from app.security import UserContext, get_current_user

router = APIRouter(prefix="/api/v1/documents", tags=["Documentos"])


# --- Schemas de Entrada e Saída ---

class DocumentTypeEnum(str, Enum):
    CONTRACT = "contract"
    INVOICE = "invoice"
    REPORT = "report"
    OTHER = "other"


class DocumentSearchFilter(BaseModel):
    query: Optional[str] = Field(
        None,
        min_length=2,
        description="Termo para busca textual no título ou conteúdo"
    )
    doc_type: Optional[DocumentTypeEnum] = Field(
        None,
        description="Filtro por tipo de documento"
    )
    author_id: Optional[UUID] = Field(
        None,
        description="Filtro por autor do documento"
    )
    date_from: Optional[datetime] = Field(
        None,
        description="Data/hora inicial da criação"
    )
    date_to: Optional[datetime] = Field(
        None,
        description="Data/hora final da criação"
    )


class DocumentResponse(BaseModel):
    id: UUID
    title: str
    content_summary: str
    doc_type: DocumentTypeEnum
    author_id: UUID
    created_at: datetime

    class Config:
        from_attributes = True


class PaginatedDocumentResponse(BaseModel):
    items: List[DocumentResponse]
    page: int
    page_size: int
    total_items: int


# --- Endpoint de Busca ---

@router.get("/search", response_model=PaginatedDocumentResponse)
async def search_documents(
    search_params: DocumentSearchFilter = Depends(),
    page: int = Query(1, ge=1, description="Número da página"),
    page_size: int = Query(20, ge=1, le=100, description="Itens por página"),
    current_user: UserContext = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)):
    """
    Realiza busca textual com múltiplos filtros opcionais combináveis em documentos.
    Garante o isolamento do tenant filtrando estritamente pelo tenant_id do usuário autenticado.
    """

    # 1. Regra de Ouro Multi-tenant: Sempre filtrar por tenant_id do contexto autenticado
    stmt = select(DocumentModel).where(
        DocumentModel.tenant_id == current_user.tenant_id,
        DocumentModel.is_deleted == False
    )

    # 2. Aplicação dinâmica dos filtros opcionais
    if search_params.query:
        # Busca textual simples utilizando ILIKE (case-insensitive)
        # Para volumes massivos, recomenda-se PostgreSQL Full-Text Search (to_tsquery)
        search_term = f"%{search_params.query}%"
        stmt = stmt.where(
            or_(
                DocumentModel.title.ilike(search_term),
                DocumentModel.content.ilike(search_term)
            )
        )

    if search_params.doc_type:
        stmt = stmt.where(DocumentModel.doc_type == search_params.doc_type)

    if search_params.author_id:
        stmt = stmt.where(DocumentModel.author_id == search_params.author_id)

    if search_params.date_from:
        stmt = stmt.where(DocumentModel.created_at >= search_params.date_from)

    if search_params.date_to:
        stmt = stmt.where(DocumentModel.created_at <= search_params.date_to)

    # Validation: date_from deve ser anterior a date_to
    if search_params.date_from and search_params.date_to:
        if search_params.date_from > search_params.date_to:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A data inicial (date_from) não pode ser posterior à data final (date_to)."
            )

    # 3. Paginação e Ordenação
    stmt = stmt.order_by(DocumentModel.created_at.desc())

    # Contagem básica para metadados (Query simplificada)
    total_result = await db.execute(stmt)
    total_items = len(total_result.scalars().all())

    # Aplicação do OFFSET e LIMIT
    offset = (page - 1) * page_size
    stmt = stmt.offset(offset).limit(page_size)

    # Execução final da query
    result = await db.execute(stmt)
    documents = result.scalars().all()

    return PaginatedDocumentResponse(
        items=documents,
        page=page,
        page_size=page_size,
        total_items=total_items
    )