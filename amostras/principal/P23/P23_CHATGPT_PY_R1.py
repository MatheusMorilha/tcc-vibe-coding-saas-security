from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import DateTime, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
import json


# ============================================================
# Configuração
# ============================================================

DATABASE_URL= "sqlite:///./app.db"

engine= create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread":False},
)

SessionLocal= sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


# ============================================================
# Banco de dados
# ============================================================

class Base(DeclarativeBase):
    pass


class Draft(Base):
    __tablename__= "drafts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Isolamento do tenant.
    tenant_id: Mapped[int] = mapped_column(
        Integer,
        index=True,
        nullable=False,
    )

    # Usuário proprietário do rascunho.
    user_id: Mapped[int] = mapped_column(
        Integer,
        index=True,
        nullable=False,
    )

    form_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    # Dados serializados do formulário.
    payload: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


Base.metadata.create_all(engine)


def get_db():
    db= SessionLocal()

    try:
        yield db
    finally:
        db.close()


# ============================================================
# Autenticação / contexto do tenant
# ============================================================

class CurrentUser(BaseModel):
    user_id: int
    tenant_id: int


def get_current_user(
    x_user_id: int = Header(...),
    x_tenant_id: int = Header(...),
)-> CurrentUser:
    """
    Exemplo simplificado.

    Em produção, esses valores devem vir de um token
    autenticado, e NÃO de headers fornecidos livremente
    pelo cliente.
    """

    return CurrentUser(
        user_id=x_user_id,
        tenant_id=x_tenant_id,
    )


# ============================================================
# Modelos da API
# ============================================================

class SaveDraftRequest(BaseModel):
    form_type: str
    data: dict[str, Any]


class DraftResponse(BaseModel):
    id: int
    form_type: str
    data: dict[str, Any]
    created_at: datetime
    updated_at: datetime

    model_config= ConfigDict(from_attributes=True)


# ============================================================
# Reconstrução do objeto
# ============================================================

class FormDraft:
    """
    Objeto de domínio reconstruído a partir do rascunho
    persistido.
    """

    def __init__(
        self,
        form_type: str,
        data: dict[str, Any],
    ):
        self.form_type= form_type
        self.data= data

    def to_dict(self)-> dict[str, Any]:
        return {
            "form_type": self.form_type,
            "data": self.data,
        }


def serialize_form(data: dict[str, Any])-> str:
    """
    Converte o objeto do formulário para uma representação
    persistível.
    """

    return json.dumps(
        data,
        ensure_ascii=False,
        separators=(",",":"),
    )


def deserialize_form(
    form_type: str,
    payload: str,
)-> FormDraft:
    """
    Reconstrói o objeto que havia sido salvo.
    """

    try:
        data= json.loads(payload)
    except json.JSONDecodeErroras exc:
        raise HTTPException(
            status_code=500,
            detail="O rascunho armazenado é inválido.",
        ) from exc

    if not isinstance(data,dict):
        raise HTTPException(
            status_code=500,
            detail="O conteúdo do rascunho possui formato inválido.",
        )

    return FormDraft(
        form_type=form_type,
        data=data,
    )


# ============================================================
# Aplicação
# ============================================================

app= FastAPI(
    title="SaaS Draft API",
)


# ============================================================
# Criar / salvar rascunho
# ============================================================

@app.post(
    "/api/v1/drafts",
    response_model=DraftResponse,
)
def save_draft(
    request: SaveDraftRequest,
    current_user: CurrentUser= Depends(get_current_user),
    db: Session= Depends(get_db),
):
    """
    Persiste um novo rascunho.

    O tenant_id é obtido do contexto autenticado e nunca
    do payload enviado pelo cliente.
    """

    now= datetime.now(timezone.utc)

    draft= Draft(
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        form_type=request.form_type,
        payload=serialize_form(request.data),
        created_at=now,
        updated_at=now,
    )

    db.add(draft)
    db.commit()
    db.refresh(draft)

    restored= deserialize_form(
        draft.form_type,
        draft.payload,
    )

    return DraftResponse(
        id=draft.id,
        form_type=restored.form_type,
        data=restored.data,
        created_at=draft.created_at,
        updated_at=draft.updated_at,
    )


# ============================================================
# Atualizar rascunho existente
# ============================================================

@app.put(
    "/api/v1/drafts/{draft_id}",
    response_model=DraftResponse,
)
def update_draft(
    draft_id: int,
    request: SaveDraftRequest,
    current_user: CurrentUser= Depends(get_current_user),
    db: Session= Depends(get_db),
):
    """
    Atualiza somente o rascunho pertencente ao usuário
    dentro do tenant autenticado.
    """

    statement= select(Draft).where(
        Draft.id== draft_id,
        Draft.tenant_id== current_user.tenant_id,
        Draft.user_id== current_user.user_id,
    )

    draft= db.scalar(statement)

    if draftis None:
        raise HTTPException(
            status_code=404,
            detail="Rascunho não encontrado.",
        )

    draft.form_type= request.form_type
    draft.payload= serialize_form(request.data)
    draft.updated_at= datetime.now(timezone.utc)

    db.commit()
    db.refresh(draft)

    restored= deserialize_form(
        draft.form_type,
        draft.payload,
    )

    return DraftResponse(
        id=draft.id,
        form_type=restored.form_type,
        data=restored.data,
        created_at=draft.created_at,
        updated_at=draft.updated_at,
    )


# ============================================================
# Restaurar rascunho
# ============================================================

@app.get(
    "/api/v1/drafts/{draft_id}",
    response_model=DraftResponse,
)
def restore_draft(
    draft_id: int,
    current_user: CurrentUser= Depends(get_current_user),
    db: Session= Depends(get_db),
):
    """
    Busca e reconstrói o objeto anteriormente persistido.
    """

    statement= select(Draft).where(
        Draft.id== draft_id,

        # Regra fundamental de isolamento:
        Draft.tenant_id== current_user.tenant_id,

        # Impede acesso a rascunhos de outro usuário.
        Draft.user_id== current_user.user_id,
    )

    draft= db.scalar(statement)

    if draftis None:
        raise HTTPException(
            status_code=404,
            detail="Rascunho não encontrado.",
        )

    restored= deserialize_form(
        draft.form_type,
        draft.payload,
    )

    return DraftResponse(
        id=draft.id,
        form_type=restored.form_type,
        data=restored.data,
        created_at=draft.created_at,
        updated_at=draft.updated_at,
    )


# ============================================================
# Listar rascunhos do usuário
# ============================================================

@app.get(
    "/api/v1/drafts",
    response_model=list[DraftResponse],
)
def list_drafts(
    current_user: CurrentUser= Depends(get_current_user),
    db: Session= Depends(get_db),
):
    """
    Lista exclusivamente os rascunhos do usuário dentro
    do tenant atual.
    """

    statement= (
        select(Draft)
        .where(
            Draft.tenant_id== current_user.tenant_id,
            Draft.user_id== current_user.user_id,
        )
        .order_by(Draft.updated_at.desc())
    )

    drafts= db.scalars(statement).all()

    result= []

    for draftin drafts:
        restored= deserialize_form(
            draft.form_type,
            draft.payload,
        )

        result.append(
            DraftResponse(
                id=draft.id,
                form_type=restored.form_type,
                data=restored.data,
                created_at=draft.created_at,
                updated_at=draft.updated_at,
            )
        )

    return result


# ============================================================
# Excluir rascunho
# ============================================================

@app.delete(
    "/api/v1/drafts/{draft_id}",
    status_code=204,
)
def delete_draft(
    draft_id: int,
    current_user: CurrentUser= Depends(get_current_user),
    db: Session= Depends(get_db),
):
    statement= select(Draft).where(
        Draft.id== draft_id,
        Draft.tenant_id== current_user.tenant_id,
        Draft.user_id== current_user.user_id,
    )

    draft= db.scalar(statement)

    if draftis None:
        raise HTTPException(
            status_code=404,
            detail="Rascunho não encontrado.",
        )

    db.delete(draft)
    db.commit()