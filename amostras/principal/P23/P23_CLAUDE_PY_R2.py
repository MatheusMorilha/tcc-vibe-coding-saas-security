# drafts.py
from __future__ import annotations

import json
import uuid
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Annotated, Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import (JSON, DateTime, Integer, String, UniqueConstraint,
                        Index, select)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# --------------------------------------------------------------------------
# Infra assumida (já existente na aplicação)
# --------------------------------------------------------------------------
# get_db()            -> Session
# get_current_user()  -> CurrentUser (resolvido a partir do JWT/sessão,
#                        NUNCA a partir de parâmetros enviados pelo cliente)
# --------------------------------------------------------------------------
from app.deps import get_db, get_current_user, CurrentUser  # noqa


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Modelo de persistência
# --------------------------------------------------------------------------
class FormDraft(Base):
    __tablename__ = "form_drafts"
    __table_args__ = (
        # Um rascunho por (empresa, usuário, tipo de formulário)
        UniqueConstraint("tenant_id", "user_id", "form_type",
                         name="uq_draft_tenant_user_form"),
        Index("ix_draft_tenant_user", "tenant_id", "user_id"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    form_type: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# --------------------------------------------------------------------------
# Schemas de rascunho (todos os campos opcionais: é um rascunho)
# Cada form_type permitido é registrado explicitamente (allowlist).
# --------------------------------------------------------------------------
class DraftBase(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class EnderecoDraft(DraftBase):
    logradouro: Optional[str] = Field(None, max_length=200)
    numero: Optional[str] = Field(None, max_length=20)
    cidade: Optional[str] = Field(None, max_length=100)
    uf: Optional[str] = Field(None, min_length=2, max_length=2)
    cep: Optional[str] = Field(None, max_length=9)


class ClienteDraft(DraftBase):
    razao_social: Optional[str] = Field(None, max_length=200)
    cnpj: Optional[str] = Field(None, max_length=18)
    email: Optional[str] = Field(None, max_length=254)
    data_fundacao: Optional[date] = None
    limite_credito: Optional[Decimal] = Field(None, ge=0, max_digits=14,
                                              decimal_places=2)
    endereco: Optional[EnderecoDraft] = None
    observacoes: Optional[str] = Field(None, max_length=5000)


class PedidoItemDraft(DraftBase):
    produto_id: Optional[str] = Field(None, max_length=36)
    quantidade: Optional[int] = Field(None, ge=0, le=1_000_000)


class PedidoDraft(DraftBase):
    cliente_id: Optional[str] = Field(None, max_length=36)
    itens: list[PedidoItemDraft] = Field(default_factory=list, max_length=200)
    observacoes: Optional[str] = Field(None, max_length=5000)


# form_type -> (versão atual do schema, classe)
DRAFT_REGISTRY: dict[str, tuple[int, type[DraftBase]]] = {
    "cliente": (1, ClienteDraft),
    "pedido": (1, PedidoDraft),
}

FormType = Literal["cliente", "pedido"]  # mantenha em sincronia com o registry
MAX_PAYLOAD_BYTES = 256 * 1024


# --------------------------------------------------------------------------
# Schemas de entrada/saída da API
# --------------------------------------------------------------------------
class DraftIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    data: dict[str, Any]
    # controle otimista de concorrência (opcional): revisão que o cliente viu
    expected_revision: Optional[int] = Field(None, ge=1)


class DraftOut(BaseModel):
    form_type: str
    revision: int
    schema_version: int
    updated_at: datetime
    data: dict[str, Any]


# --------------------------------------------------------------------------
# Dependências de segurança
# --------------------------------------------------------------------------
def require_active_subscription(
        user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if not user.tenant_subscription_active:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED,
                            "Assinatura inativa.")
    return user


def _scoped(user: CurrentUser, form_type: str):
    """Toda consulta é filtrada por tenant E usuário, vindos do token."""
    return select(FormDraft).where(
        FormDraft.tenant_id == user.tenant_id,
        FormDraft.user_id == user.id,
        FormDraft.form_type == form_type,
    )


def _build_draft_object(form_type: str, raw: dict[str, Any]) -> DraftBase:
    version, model = DRAFT_REGISTRY[form_type]
    return model.model_validate(raw)


# --------------------------------------------------------------------------
# Rotas
# --------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/drafts", tags=["drafts"])


@router.put("/{form_type}", response_model=DraftOut)
def save_draft(
    body: DraftIn,
    form_type: Annotated[FormType, Path()],
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_active_subscription),
):
    schema_version, _ = DRAFT_REGISTRY[form_type]

    # 1) Valida e normaliza no schema do formulário (rejeita campos extras)
    try:
        draft_obj = _build_draft_object(form_type, body.data)
    except ValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            exc.errors(include_url=False, include_input=False))

    # 2) Serializa para JSON puro (datas/Decimal viram string) e limita tamanho
    payload = json.loads(draft_obj.model_dump_json(exclude_none=True))
    if len(json.dumps(payload).encode()) > MAX_PAYLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            "Rascunho excede o tamanho máximo.")

    # 3) Upsert escopado por tenant + usuário
    for _ in range(2):  # 2ª tentativa cobre corrida no INSERT
        row = db.execute(_scoped(user, form_type).with_for_update()
                         ).scalar_one_or_none()
        try:
            if row is None:
                row = FormDraft(
                    tenant_id=user.tenant_id, user_id=user.id,
                    form_type=form_type, schema_version=schema_version,
                    payload=payload, revision=1)
                db.add(row)
            else:
                if (body.expected_revision is not None
                        and body.expected_revision != row.revision):
                    raise HTTPException(
                        status.HTTP_409_CONFLICT,
                        "Rascunho foi alterado em outra sessão.")
                row.payload = payload
                row.schema_version = schema_version
                row.revision += 1
            db.commit()
            break
        except IntegrityError:
            db.rollback()
    else:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Conflito ao salvar o rascunho.")

    db.refresh(row)
    return DraftOut(form_type=form_type, revision=row.revision,
                    schema_version=row.schema_version,
                    updated_at=row.updated_at, data=payload)


@router.get("/{form_type}", response_model=DraftOut)
def restore_draft(
    form_type: Annotated[FormType, Path()],
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_active_subscription),
):
    row = db.execute(_scoped(user, form_type)).scalar_one_or_none()
    if row is None:
        # 404 genérico: não revela se existe rascunho de outro tenant/usuário
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "Rascunho não encontrado.")

    # Reconstrói o objeto da aplicação a partir do schema atual (revalida).
    try:
        draft_obj = _build_draft_object(row.form_type, row.payload)
    except ValidationError:
        # Schema evoluiu e o rascunho antigo ficou incompatível.
        # Aqui entraria uma migração por schema_version; sem ela, descarta-se.
        raise HTTPException(status.HTTP_410_GONE,
                            "Rascunho incompatível com a versão atual do formulário.")

    return DraftOut(
        form_type=row.form_type, revision=row.revision,
        schema_version=row.schema_version, updated_at=row.updated_at,
        data=json.loads(draft_obj.model_dump_json(exclude_none=True)))


@router.delete("/{form_type}", status_code=status.HTTP_204_NO_CONTENT)
def discard_draft(
    form_type: Annotated[FormType, Path()],
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_active_subscription),
):
    row = db.execute(_scoped(user, form_type)).scalar_one_or_none()
    if row is not None:
        db.delete(row)
        db.commit()