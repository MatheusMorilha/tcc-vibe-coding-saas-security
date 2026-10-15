from datetime import date
from enum import Enum
from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

# Imports hipotéticos da sua estrutura existente de banco de dados e autenticação
from app.database import get_db_session
from app.models import Document, DocumentType
from app.auth import UserContext, get_current_user

router = APIRouter(prefix="/documents", tags=["Documents"])


# --- Schemas de Entrada e Saída (DTOs) ---

class DocumentTypeEnum(str, Enum):
    INVOICE = "INVOICE"
    CONTRACT = "CONTRACT"
    REPORT = "REPORT"
    OTHER = "OTHER"


class DocumentResponse(BaseModel):
    id: UUID
    title: str
    type: DocumentTypeEnum
    author_id: UUID
    created_at: date

    class Config:
        from_attributes = True


class PaginatedDocumentResponse(BaseModel):
    items: List[DocumentResponse]
    total: int
    page: int
    size: int


# --- Rota da API ---

@router.get(
    "/search",
    response_model=PaginatedDocumentResponse,
    status_code=status.HTTP_200_OK,
    summary="Busca documentos com filtros avançados",
    description="Realiza busca de texto em documentos garantindo o isolamento multilocatário.")
async def search_documents(
    # Parâmetro de busca por texto (opcional ou obrigatório conforme regra)
    q: Optional[str] = Query(
        None,
        min_length=2,
        description="Termo para busca textual no título ou conteúdo"),

    # Filtros Opcionais
    doc_type: Optional[DocumentTypeEnum] = Query(None, description="Filtrar por tipo de documento"),
    author_id: Optional[UUID] = Query(None, description="Filtrar por autor do documento"),
    start_date: Optional[date] = Query(None, description="Data inicial do documento (YYYY-MM-DD)"),
    end_date: Optional[date] = Query(None, description="Data final do documento (YYYY-MM-DD)"),

    # Paginação
    page: int = Query(1, ge=1, description="Número da página"),
    size: int = Query(20, ge=1, le=100, description="Tamanho da página"),

    # Injeção de Dependências
    current_user: UserContext = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)):
    # Validação do intervalo de datas
    if start_date and end_date and start_date > end_date:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A data inicial (start_date) não pode ser posterior à data final (end_date)."
        )

    # 1. Isolamento Multilocatário Obrigatório
    # A consulta SEMPRE parte do tenant_id do usuário autenticado no token JWT
    filters = [Document.tenant_id == current_user.tenant_id]

    # 2. Aplicação Condicional da Busca Textual
    if q:
        search_pattern = f"%{q.strip()}%"
        # Busca no título ou no conteúdo do documento
        filters.append(
            (Document.title.ilike(search_pattern)) |
            (Document.content.ilike(search_pattern))
        )

    # 3. Aplicação dos Filtros Opcionais Combináveis
    if doc_type:
        filters.append(Document.type == doc_type.value)

    if author_id:
        filters.append(Document.author_id == author_id)

    if start_date:
        filters.append(Document.created_at >= start_date)

    if end_date:
        filters.append(Document.created_at <= end_date)

    # 4. Construção das Queries (Dados + Total para Paginação)
    base_stmt = select(Document).where(and_(*filters))

    # Query para contagem total de itens correspondentes aos filtros
    count_stmt = select(Document.id).where(and_(*filters))
    total_result = await db.execute(count_stmt)
    total = len(total_result.all())

    # Aplicação de ordenação e paginação
    offset = (page - 1) * size
    stmt = (
        base_stmt
        .order_by(Document.created_at.desc())
        .offset(offset)
        .limit(size)
    )

    result = await db.execute(stmt)
    documents = result.scalars().all()

    return PaginatedDocumentResponse(
        items=documents,
        total=total,
        page=page,
        size=size
    )