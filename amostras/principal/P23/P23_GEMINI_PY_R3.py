import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, UniqueConstraint
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class FormDraft(Base):
    __tablename__ = "form_drafts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, nullable=False, index=True)
    user_id = Column(String, nullable=False, index=True)
    form_id = Column(String, nullable=False, index=True)
    data = Column(JSON, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Garante que cada usuário tenha apenas um rascunho ativo por formulário na sua empresa
    __table_args__ = (
        UniqueConstraint('tenant_id', 'user_id', 'form_id', name='uq_tenant_user_form_draft'),
    )

from pydantic import BaseModel, Field
from typing import Dict, Any
from datetime import datetime

class DraftSaveRequest(BaseModel):
    data: Dict[str, Any] = Field(
        ...,
        description="Objeto contendo o estado/preenchimento atual do formulário"
    )

class DraftResponse(BaseModel):
    form_id: str
    data: Dict[str, Any]
    updated_at: datetime

    class Config:
        from_attributes = True

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional

from .models import FormDraft
from .schemas import DraftSaveRequest, DraftResponse

router = APIRouter(prefix="/forms", tags=["Drafts"])

# Simulação de injeção de dependência do banco de dados
def get_db():
    ...

# Simulação de extração do contexto de autenticação/multi-tenant
class AuthContext:
    def __init__(self, tenant_id: str, user_id: str):
        self.tenant_id = tenant_id
        self.user_id = user_id

def get_current_user_context() -> AuthContext:
    # Em produção, extrair do Token JWT do cabeçalho Authorization
    return AuthContext(tenant_id="tenant_123", user_id="user_456")


@router.put("/{form_id}/draft", response_model=DraftResponse, status_code=status.HTTP_200_OK)
def save_draft(
    form_id: str,
    payload: DraftSaveRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_user_context)):
    """
    Persiste ou atualiza (upsert) o rascunho de um formulário para o usuário/locatário.
    """
    draft = db.query(FormDraft).filter(
        FormDraft.tenant_id == auth.tenant_id,
        FormDraft.user_id == auth.user_id,
        FormDraft.form_id == form_id
    ).first()

    if draft:
        draft.data = payload.data
    else:
        draft = FormDraft(
            tenant_id=auth.tenant_id,
            user_id=auth.user_id,
            form_id=form_id,
            data=payload.data
        )
        db.add(draft)

    db.commit()
    db.refresh(draft)

    return draft


@router.get("/{form_id}/draft", response_model=DraftResponse)
def restore_draft(
    form_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_user_context)):
    """
    Recupera o rascunho e reconstrói o objeto do formulário salvo.
    """
    draft = db.query(FormDraft).filter(
        FormDraft.tenant_id == auth.tenant_id,
        FormDraft.user_id == auth.user_id,
        FormDraft.form_id == form_id
    ).first()

    if not draft:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nenhum rascunho encontrado para este formulário."
        )

    return draft


@router.delete("/{form_id}/draft", status_code=status.HTTP_204_NO_CONTENT)
def discard_draft(
    form_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_user_context)):
    """
    Remove o rascunho após o envio final com sucesso do formulário.
    """
    draft = db.query(FormDraft).filter(
        FormDraft.tenant_id == auth.tenant_id,
        FormDraft.user_id == auth.user_id,
        FormDraft.form_id == form_id
    ).first()

    if draft:
        db.delete(draft)
        db.commit()

    return None