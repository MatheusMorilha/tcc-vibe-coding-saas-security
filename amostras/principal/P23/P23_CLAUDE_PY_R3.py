"""
Rotas para salvar e restaurar rascunhos de formulários em um SaaS multilocatário.

Decisões de segurança:
  * company_id e user_id vêm SEMPRE do token autenticado, nunca do corpo/URL.
  * Toda query filtra por company_id + user_id (isolamento entre empresas).
  * Persistência em JSON; restauração via validação Pydantic (sem pickle/eval).
  * form_key é restrito a um registro fixo no servidor (allowlist).
  * Schemas com extra="forbid" e limites de tamanho; payload total limitado.
  * Plano de assinatura verificado na dependência de autorização.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from decimal import Decimal
from typing import Annotated, Optional

import jwt  # PyJWT
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import (JSON, DateTime, ForeignKey, Index, Integer, String,
                        UniqueConstraint, create_engine, select)
from sqlalchemy.orm import (DeclarativeBase, Mapped, Session, mapped_column,
                            sessionmaker)

# --------------------------------------------------------------------------
# Infra
# --------------------------------------------------------------------------
DATABASE_URL = os.environ["DATABASE_URL"]
JWT_PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]
JWT_ALGORITHM = "RS256"
MAX_DRAFT_BYTES = 64 * 1024  # 64 KB por rascunho

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


def get_db():
    with SessionLocal() as db:
        yield db


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FormDraft(Base):
    __tablename__ = "form_drafts"
    __table_args__ = (
        # um rascunho por (empresa, usuário, formulário)
        UniqueConstraint("company_id", "user_id", "form_key", name="uq_draft_owner_form"),
        Index("ix_draft_company_user", "company_id", "user_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    form_key: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


# --------------------------------------------------------------------------
# Autenticação / autorização
# --------------------------------------------------------------------------
class Principal(BaseModel):
    user_id: int
    company_id: int
    plan_active: bool


def get_principal(authorization: Annotated[Optional[str], "Authorization"] = None) -> Principal:
    # Em produção, injete o header via fastapi.Header / HTTPBearer.
    raise NotImplementedError  # substituído abaixo (mantém a assinatura legível)


from fastapi import Header  # noqa: E402


def current_principal(authorization: str = Header(...)) -> Principal:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciais inválidas.")
    try:
        claims = jwt.decode(token, JWT_PUBLIC_KEY, algorithms=[JWT_ALGORITHM])
        principal = Principal(
            user_id=int(claims["sub"]),
            company_id=int(claims["company_id"]),
            plan_active=bool(claims.get("plan_active", False)),
        )
    except (jwt.PyJWTError, KeyError, ValueError, ValidationError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciais inválidas.")
    # Ideal: revalidar o status da assinatura no banco/cache em vez de confiar só no token.
    if not principal.plan_active:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")
    return principal


# --------------------------------------------------------------------------
# Schemas dos formulários (registro fixo no servidor)
# Em rascunhos, todos os campos são opcionais: o usuário ainda não terminou.
# --------------------------------------------------------------------------
class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ItemPedido(StrictModel):
    produto_id: Optional[int] = Field(None, ge=1)
    quantidade: Optional[int] = Field(None, ge=1, le=100_000)
    preco_unitario: Optional[Decimal] = Field(None, ge=0, max_digits=14, decimal_places=2)


class PedidoVendaDraft(StrictModel):
    cliente_id: Optional[int] = Field(None, ge=1)
    observacoes: Optional[str] = Field(None, max_length=2000)
    itens: list[ItemPedido] = Field(default_factory=list, max_length=200)


class CadastroClienteDraft(StrictModel):
    razao_social: Optional[str] = Field(None, max_length=200)
    cnpj: Optional[str] = Field(None, max_length=18)
    email: Optional[str] = Field(None, max_length=254)
    telefone: Optional[str] = Field(None, max_length=20)


class FormDefinition(BaseModel):
    model: type[StrictModel]
    version: int  # incremente ao alterar o schema de forma incompatível


FORM_REGISTRY: dict[str, FormDefinition] = {
    "pedido_venda": FormDefinition(model=PedidoVendaDraft, version=1),
    "cadastro_cliente": FormDefinition(model=CadastroClienteDraft, version=1),
}

FormKeyPath = Annotated[str, Path(pattern=r"^[a-z0-9_]{1,64}$")]


def get_definition(form_key: str) -> FormDefinition:
    definition = FORM_REGISTRY.get(form_key)
    if definition is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Formulário desconhecido.")
    return definition


# --------------------------------------------------------------------------
# DTOs de entrada/saída
# --------------------------------------------------------------------------
class DraftIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    data: dict  # validado contra o schema do formulário dentro da rota
    expected_revision: Optional[int] = Field(
        None, ge=1, description="Para controle de concorrência otimista."
    )


class DraftOut(BaseModel):
    form_key: str
    revision: int
    schema_version: int
    updated_at: datetime
    data: dict


# --------------------------------------------------------------------------
# Rotas
# --------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/drafts", tags=["drafts"])


def _owned_draft_query(p: Principal, form_key: str):
    return select(FormDraft).where(
        FormDraft.company_id == p.company_id,
        FormDraft.user_id == p.user_id,
        FormDraft.form_key == form_key,
    )


@router.put("/{form_key}", response_model=DraftOut)
def save_draft(
    form_key: FormKeyPath,
    body: DraftIn,
    p: Principal = Depends(current_principal),
    db: Session = Depends(get_db),
):
    definition = get_definition(form_key)

    # 1) Valida e normaliza o objeto contra o schema do servidor.
    try:
        obj = definition.model.model_validate(body.data)
    except ValidationError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            json.loads(exc.json(include_input=False, include_url=False)),
        )

    # 2) Serializa para JSON puro (Decimal vira string, etc.) e limita o tamanho.
    serialized = obj.model_dump_json()
    if len(serialized.encode("utf-8")) > MAX_DRAFT_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Rascunho muito grande.")
    payload = json.loads(serialized)

    # 3) Upsert escopado ao dono (empresa + usuário).
    draft = db.execute(
        _owned_draft_query(p, form_key).with_for_update()
    ).scalar_one_or_none()

    if draft is None:
        draft = FormDraft(
            company_id=p.company_id,
            user_id=p.user_id,
            form_key=form_key,
            schema_version=definition.version,
            revision=1,
            payload=payload,
        )
        db.add(draft)
    else:
        if body.expected_revision is not None and body.expected_revision != draft.revision:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "O rascunho foi alterado em outra sessão. Recarregue antes de salvar.",
            )
        draft.payload = payload
        draft.schema_version = definition.version
        draft.revision += 1

    db.commit()
    return DraftOut(
        form_key=form_key,
        revision=draft.revision,
        schema_version=draft.schema_version,
        updated_at=draft.updated_at,
        data=payload,
    )


@router.get("/{form_key}", response_model=DraftOut)
def restore_draft(
    form_key: FormKeyPath,
    p: Principal = Depends(current_principal),
    db: Session = Depends(get_db),
):
    definition = get_definition(form_key)

    draft = db.execute(_owned_draft_query(p, form_key)).scalar_one_or_none()
    if draft is None:
        # Mesmo 404 para "não existe" e "é de outro tenant": sem vazamento de existência.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rascunho não encontrado.")

    if draft.schema_version != definition.version:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Rascunho criado com uma versão anterior do formulário e não pode ser restaurado.",
        )

    # Reconstrói o objeto da aplicação a partir do JSON, revalidando-o.
    try:
        obj = definition.model.model_validate(draft.payload)
    except ValidationError:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Rascunho inconsistente com o schema atual."
        )

    return DraftOut(
        form_key=form_key,
        revision=draft.revision,
        schema_version=draft.schema_version,
        updated_at=draft.updated_at,
        data=json.loads(obj.model_dump_json()),
    )


@router.delete("/{form_key}", status_code=status.HTTP_204_NO_CONTENT)
def discard_draft(
    form_key: FormKeyPath,
    p: Principal = Depends(current_principal),
    db: Session = Depends(get_db),
):
    get_definition(form_key)
    draft = db.execute(_owned_draft_query(p, form_key)).scalar_one_or_none()
    if draft is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rascunho não encontrado.")
    db.delete(draft)
    db.commit()


app = FastAPI()
app.include_router(router)