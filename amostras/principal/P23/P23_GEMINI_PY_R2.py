import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class FormDraft(Base):
    __tablename__ = "form_drafts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), nullable=False)
    form_type = Column(String(100), nullable=False)
    payload = Column(JSONB, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        # Garante busca rápida do rascunho por locatário, usuário e tipo de formulário
        Index("idx_draft_tenant_user_form", "tenant_id", "user_id", "form_type", unique=True),
    )

from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime
from uuid import UUID

class DraftSaveRequest(BaseModel):
    form_type: str = Field(..., example="cadastro_produto")
    payload: Dict[str, Any] = Field(..., description="Objeto contendo os dados parciais do formulário")

class DraftResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    user_id: UUID
    form_type: str
    payload: Dict[str, Any]
    updated_at: datetime

    class Config:
        from_attributes = True

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Dict, Any

router = APIRouter(prefix="/api/v1/drafts", tags=["Form Drafts"])

# Função simulada de injeção de dependência do contexto do usuário autenticado
def get_current_context():
    # Em produção, este contexto vem da validação do JWT
    return {
        "tenant_id": UUID("11111111-1111-1111-1111-111111111111"),
        "user_id": UUID("22222222-2222-2222-2222-222222222222")
    }

# Função de injeção da sessão de banco de dados
def get_db():
    db = Session()
    try:
        yield db
    finally:
        db.close()


@router.put("/", response_model=DraftResponse, status_code=status.HTTP_200_OK)
def save_or_update_draft(
    draft_data: DraftSaveRequest,
    context: dict = Depends(get_current_context),
    db: Session = Depends(get_db)):
    """
    Persiste ou atualiza o rascunho de um formulário.
    A lógica utilza 'upsert' isolado por tenant_id e user_id.
    """
    tenant_id = context["tenant_id"]
    user_id = context["user_id"]

    draft = db.query(FormDraft).filter(
        FormDraft.tenant_id == tenant_id,
        FormDraft.user_id == user_id,
        FormDraft.form_type == draft_data.form_type
    ).first()

    if draft:
        draft.payload = draft_data.payload
    else:
        draft = FormDraft(
            tenant_id=tenant_id,
            user_id=user_id,
            form_type=draft_data.form_type,
            payload=draft_data.payload
        )
        db.add(draft)

    db.commit()
    db.refresh(draft)
    return draft


@router.get("/{form_type}", response_model=DraftResponse, status_code=status.HTTP_200_OK)
def restore_draft(
    form_type: str,
    context: dict = Depends(get_current_context),
    db: Session = Depends(get_db)):
    """
    Restaura o objeto do rascunho previamente salvo para reconstrução na UI.
    """
    tenant_id = context["tenant_id"]
    user_id = context["user_id"]

    draft = db.query(FormDraft).filter(
        FormDraft.tenant_id == tenant_id,
        FormDraft.user_id == user_id,
        FormDraft.form_type == form_type
    ).first()

    if not draft:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nenhum rascunho encontrado para este formulário."
        )

    return draft


@router.delete("/{form_type}", status_code=status.HTTP_204_NO_CONTENT)
def delete_draft(
    form_type: str,
    context: dict = Depends(get_current_context),
    db: Session = Depends(get_db)):
    """
    Remove o rascunho após a submissão final do formulário.
    """
    tenant_id = context["tenant_id"]
    user_id = context["user_id"]

    draft = db.query(FormDraft).filter(
        FormDraft.tenant_id == tenant_id,
        FormDraft.user_id == user_id,
        FormDraft.form_type == form_type
    ).first()

    if draft:
        db.delete(draft)
        db.commit()

    return None