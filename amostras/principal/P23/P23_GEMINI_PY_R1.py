from datetime import datetime, timezone
import uuid
from sqlalchemy import JSON, Column, DateTime, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class FormDraft(Base):
    __tablename__ = "form_drafts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    form_type = Column(
        String(100), nullable=False
    )  # Ex: 'client_onboarding', 'financial_entry'
    payload = Column(
        JSON, nullable=False
    )  # Armazena o estado bruto do formulário
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        # Garante que cada usuário tenha apenas 1 rascunho por tipo de formulário no seu locatário
        UniqueConstraint(
            "tenant_id",
            "user_id",
            "form_type",
            name="uq_tenant_user_form_draft",
        ),
    )

from datetime import datetime
from typing import Any, Dict
from uuid import UUID
from pydantic import BaseModel, Field


# Objeto enviado pelo front-end para salvar/atualizar
class SaveDraftRequest(BaseModel):
    form_type: str = Field(
        ...,
        max_length=100,
        description="Identificador único do tipo de formulário",
    )
    payload: Dict[str, Any] = Field(
        ...,
        description="Objeto JSON contendo os dados parciais do formulário",
    )


# Resposta da API ao consultar um rascunho
class DraftResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    user_id: UUID
    form_type: str
    payload: Dict[str, Any]
    updated_at: datetime

    class Config:
        from_attributes = True

from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

# Presuma a existência de uma dependência de injeção da sessão de banco e contexto do usuário logado
# from app.database import get_db
# from app.auth import get_current_user_context

router = APIRouter(prefix="/api/v1/drafts", tags=["Form Drafts"])


# Contexto injetado do locatário e usuário logado extraído do JWT Token
class UserContext:
    def __init__(self, tenant_id: UUID, user_id: UUID):
        self.tenant_id = tenant_id
        self.user_id = user_id


@router.put("/", response_model=DraftResponse, status_code=status.HTTP_200_OK)
async def save_or_update_draft(
    draft_in: SaveDraftRequest,
    ctx: Annotated[UserContext, Depends(get_current_user_context)],
    db: Annotated[AsyncSession, Depends(get_db)],):
    """
    Persiste ou atualiza o rascunho de um formulário.
    Usa comportamento de Upsert isolado estritamente por tenant_id e user_id.
    """
    # Query PostgreSQL ON CONFLICT (Upsert)
    stmt = (
        insert(FormDraft)
        .values(
            tenant_id=ctx.tenant_id,
            user_id=ctx.user_id,
            form_type=draft_in.form_type,
            payload=draft_in.payload,
        )
        .on_conflict_do_update(
            constraint="uq_tenant_user_form_draft",
            set_={
                "payload": draft_in.payload,
                "updated_at": select(FormDraft.updated_at).as_scalar(),  # Força atualização
            },
        )
        .returning(FormDraft)
    )

    result = await db.execute(stmt)
    await db.commit()
    draft = result.scalar_one()

    return draft


@router.get("/{form_type}", response_model=DraftResponse)
async def get_draft(
    form_type: str,
    ctx: Annotated[UserContext, Depends(get_current_user_context)],
    db: Annotated[AsyncSession, Depends(get_db)],):
    """
    Restaura o rascunho salvo do formulário solicitante para que a aplicação
    reconstrua a interface com o estado anterior do objeto.
    """
    # Consulta filtrando OBRIGATORIAMENTE por tenant_id e user_id
    stmt = select(FormDraft).where(
        FormDraft.tenant_id == ctx.tenant_id,
        FormDraft.user_id == ctx.user_id,
        FormDraft.form_type == form_type,
    )

    result = await db.execute(stmt)
    draft = result.scalar_one_or_none()

    if not draft:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Nenhum rascunho encontrado para o formulário '{form_type}'.",
        )

    return draft


@router.delete("/{form_type}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_draft(
    form_type: str,
    ctx: Annotated[UserContext, Depends(get_current_user_context)],
    db: Annotated[AsyncSession, Depends(get_db)],):
    """
    Remove o rascunho após a submissão final com sucesso do formulário.
    """
    stmt = select(FormDraft).where(
        FormDraft.tenant_id == ctx.tenant_id,
        FormDraft.user_id == ctx.user_id,
        FormDraft.form_type == form_type,
    )

    result = await db.execute(stmt)
    draft = result.scalar_one_or_none()

    if draft:
        await db.delete(draft)
        await db.commit()

    return None