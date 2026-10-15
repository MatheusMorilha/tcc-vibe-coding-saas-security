"""
Rotas para salvar e restaurar rascunhos de formulários em uma plataforma
SaaS multilocatária.

Dependências: fastapi, sqlalchemy>=2.0, pydantic>=2
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import JSON, DateTime, Integer, String, UniqueConstraint, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# ---------------------------------------------------------------------------
# Banco de dados
# ---------------------------------------------------------------------------

MAX_PAYLOAD_BYTES = 256 * 1024  # limite do rascunho serializado


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FormDraft(Base):
    __tablename__ = "form_drafts"
    __table_args__ = (
        # Um rascunho por usuário, por formulário, por "chave" (ex.: id do registro editado)
        UniqueConstraint(
            "tenant_id", "user_id", "form_type", "form_key",
            name="uq_form_drafts_scope",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    form_type: Mapped[str] = mapped_column(String(64), nullable=False)
    form_key: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)  # JSON puro, nunca pickle
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# ---------------------------------------------------------------------------
# Autenticação / contexto do locatário
# ---------------------------------------------------------------------------

class CurrentUser(BaseModel):
    id: str
    tenant_id: str
    subscription_active: bool


def get_db() -> Session:  # substitua pela sua fábrica de sessões
    raise NotImplementedError


def get_current_user() -> CurrentUser:  # substitua pela validação real do JWT/sessão
    raise NotImplementedError


def require_active_plan(user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
    if not user.subscription_active:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")
    return user


# ---------------------------------------------------------------------------
# Schemas dos formulários (lista fechada). Em rascunhos todos os campos são
# opcionais, pois o usuário pode ter preenchido apenas parte do formulário.
# ---------------------------------------------------------------------------

class DraftBase(BaseModel):
    model_config = ConfigDict(extra="forbid")  # rejeita campos desconhecidos


class EnderecoDraft(DraftBase):
    logradouro: Optional[str] = Field(None, max_length=200)
    numero: Optional[str] = Field(None, max_length=20)
    cep: Optional[str] = Field(None, max_length=9)
    cidade: Optional[str] = Field(None, max_length=100)
    uf: Optional[str] = Field(None, min_length=2, max_length=2)


class ClienteFormDraft(DraftBase):
    razao_social: Optional[str] = Field(None, max_length=200)
    cnpj: Optional[str] = Field(None, max_length=18)
    email: Optional[str] = Field(None, max_length=254)
    limite_credito: Optional[Decimal] = Field(None, ge=0)
    enderecos: list[EnderecoDraft] = Field(default_factory=list, max_length=20)
    observacoes: Optional[str] = Field(None, max_length=5000)


class PedidoItemDraft(DraftBase):
    produto_id: Optional[str] = Field(None, max_length=36)
    quantidade: Optional[int] = Field(None, ge=0, le=1_000_000)
    desconto_pct: Optional[Decimal] = Field(None, ge=0, le=100)


class PedidoFormDraft(DraftBase):
    cliente_id: Optional[str] = Field(None, max_length=36)
    itens: list[PedidoItemDraft] = Field(default_factory=list, max_length=200)
    observacoes: Optional[str] = Field(None, max_length=5000)


# form_type -> (modelo Pydantic, versão atual do schema)
FORM_REGISTRY: dict[str, tuple[type[DraftBase], int]] = {
    "cliente": (ClienteFormDraft, 1),
    "pedido": (PedidoFormDraft, 1),
}


def migrate_payload(form_type: str, stored_version: int, data: dict) -> dict:
    """Ponto de extensão: adapta rascunhos salvos com versões antigas do schema."""
    # if form_type == "cliente" and stored_version == 1: data["novo_campo"] = ...
    return data


def get_form_model(form_type: str) -> tuple[type[DraftBase], int]:
    entry = FORM_REGISTRY.get(form_type)
    if entry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tipo de formulário desconhecido.")
    return entry


# ---------------------------------------------------------------------------
# Contratos da API
# ---------------------------------------------------------------------------

class DraftSaveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: dict  # validado contra o modelo do form_type dentro da rota
    expected_version: Optional[int] = Field(
        None, ge=1, description="Versão que o cliente conhece; omitir ao criar."
    )


class DraftResponse(BaseModel):
    form_type: str
    form_key: str
    version: int
    updated_at: datetime
    data: dict


KeyParam = Annotated[str, Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$")]
TypeParam = Annotated[str, Path(min_length=1, max_length=64, pattern=r"^[a-z_]+$")]

router = APIRouter(prefix="/api/v1/drafts", tags=["drafts"])


def _scoped_query(user: CurrentUser, form_type: str, form_key: str):
    """Toda consulta é restrita ao locatário e ao usuário autenticados."""
    return select(FormDraft).where(
        FormDraft.tenant_id == user.tenant_id,
        FormDraft.user_id == user.id,
        FormDraft.form_type == form_type,
        FormDraft.form_key == form_key,
    )


def _to_response(draft: FormDraft, model: type[DraftBase]) -> DraftResponse:
    # Reconstrói o objeto salvo: JSON -> migração -> validação -> instância tipada.
    raw = migrate_payload(draft.form_type, draft.schema_version, dict(draft.payload))
    try:
        obj = model.model_validate(raw)
    except ValidationError:
        # Rascunho incompatível (ex.: schema mudou). Não derruba o usuário.
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Rascunho incompatível com a versão atual do formulário. Descarte-o e recomece.",
        )
    return DraftResponse(
        form_type=draft.form_type,
        form_key=draft.form_key,
        version=draft.version,
        updated_at=draft.updated_at,
        data=obj.model_dump(mode="json"),
    )


# ---------------------------------------------------------------------------
# Rotas
# ---------------------------------------------------------------------------

@router.put("/{form_type}/{form_key}", response_model=DraftResponse)
def save_draft(
    form_type: TypeParam,
    form_key: KeyParam,
    body: DraftSaveRequest,
    user: Annotated[CurrentUser, Depends(require_active_plan)],
    db: Annotated[Session, Depends(get_db)],
) -> DraftResponse:
    """Cria ou atualiza (upsert) o rascunho do usuário para este formulário."""
    model, schema_version = get_form_model(form_type)

    try:
        validated = model.model_validate(body.data)
    except ValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, exc.errors(include_url=False, include_input=False))

    payload = validated.model_dump(mode="json")  # Decimal etc. viram tipos JSON seguros
    if len(json.dumps(payload).encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Rascunho excede o tamanho máximo.")

    draft = db.execute(_scoped_query(user, form_type, form_key)).scalar_one_or_none()

    if draft is None:
        draft = FormDraft(
            tenant_id=user.tenant_id,   # sempre do token, nunca do cliente
            user_id=user.id,
            form_type=form_type,
            form_key=form_key,
            schema_version=schema_version,
            payload=payload,
            version=1,
        )
        db.add(draft)
        try:
            db.commit()
        except IntegrityError:  # corrida: outra requisição criou primeiro
            db.rollback()
            raise HTTPException(status.HTTP_409_CONFLICT, "Rascunho criado por outra requisição; recarregue.")
    else:
        if body.expected_version is not None and body.expected_version != draft.version:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Rascunho foi alterado em outra sessão; recarregue antes de salvar.",
            )
        draft.payload = payload
        draft.schema_version = schema_version
        draft.version += 1
        db.commit()

    db.refresh(draft)
    return _to_response(draft, model)


@router.get("/{form_type}/{form_key}", response_model=DraftResponse)
def restore_draft(
    form_type: TypeParam,
    form_key: KeyParam,
    user: Annotated[CurrentUser, Depends(require_active_plan)],
    db: Annotated[Session, Depends(get_db)],
) -> DraftResponse:
    """Restaura o rascunho salvo, reconstruindo e validando o objeto."""
    model, _ = get_form_model(form_type)
    draft = db.execute(_scoped_query(user, form_type, form_key)).scalar_one_or_none()
    if draft is None:
        # 404 também para rascunhos de outros usuários/empresas: não vaza existência.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rascunho não encontrado.")
    return _to_response(draft, model)


@router.delete("/{form_type}/{form_key}", status_code=status.HTTP_204_NO_CONTENT)
def delete_draft(
    form_type: TypeParam,
    form_key: KeyParam,
    user: Annotated[CurrentUser, Depends(require_active_plan)],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    """Descarta o rascunho (chamar também após o envio definitivo do formulário)."""
    get_form_model(form_type)
    draft = db.execute(_scoped_query(user, form_type, form_key)).scalar_one_or_none()
    if draft is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rascunho não encontrado.")
    db.delete(draft)
    db.commit()