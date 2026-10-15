"""
Rota de busca textual em documentos para plataforma SaaS multilocatária.

Stack: FastAPI + SQLAlchemy 2.0 (async) + PostgreSQL (full-text search).

Princípios de segurança:
  * O tenant_id vem SEMPRE do usuário autenticado (token), nunca da requisição.
  * O filtro por tenant é aplicado em toda query, antes de qualquer outro filtro.
  * Todas as entradas são parametrizadas (sem concatenação de SQL).
  * Tamanho de página limitado e termo de busca com tamanho mínimo/máximo.
"""
from __future__ import annotations

import enum
import uuid
from datetime import date, datetime, time, timedelta, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import (
    Computed,
    DateTime,
    Enum,
    Index,
    String,
    Text,
    func,
    select,
)
from sqlalchemy.dialects.postgresql import TSVECTOR, UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# --------------------------------------------------------------------------
# Dependências do projeto (substitua pelos módulos reais da aplicação)
# --------------------------------------------------------------------------
# from app.db import get_session
# from app.auth import get_current_user, CurrentUser
#
# CurrentUser deve expor: id: UUID, tenant_id: UUID, e já ter validado
# o token e a assinatura ativa da empresa.


# --------------------------------------------------------------------------
# Modelo
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class TipoDocumento(str, enum.Enum):
    CONTRATO = "contrato"
    NOTA_FISCAL = "nota_fiscal"
    RELATORIO = "relatorio"
    PROPOSTA = "proposta"
    OUTRO = "outro"


class Documento(Base):
    __tablename__ = "documentos"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    autor_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    tipo: Mapped[TipoDocumento] = mapped_column(Enum(TipoDocumento, name="tipo_documento"), nullable=False)
    titulo: Mapped[str] = mapped_column(String(300), nullable=False)
    conteudo: Mapped[str] = mapped_column(Text, nullable=False, default="")
    criado_em: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    excluido_em: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Coluna gerada pelo próprio banco: título tem peso A, conteúdo peso B.
    busca: Mapped[str] = mapped_column(
        TSVECTOR,
        Computed(
            "setweight(to_tsvector('portuguese', coalesce(titulo, '')), 'A') || "
            "setweight(to_tsvector('portuguese', coalesce(conteudo, '')), 'B')",
            persisted=True,
        ),
    )

    __table_args__ = (
        # Índice GIN para a busca textual.
        Index("ix_documentos_busca", "busca", postgresql_using="gin"),
        # Índice composto: o tenant sempre vem primeiro, pois sempre é filtrado.
        Index("ix_documentos_tenant_tipo_data", "tenant_id", "tipo", "criado_em"),
        Index("ix_documentos_tenant_autor_data", "tenant_id", "autor_id", "criado_em"),
    )


# --------------------------------------------------------------------------
# Schemas de resposta
# --------------------------------------------------------------------------
class DocumentoResumo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    titulo: str
    tipo: TipoDocumento
    autor_id: uuid.UUID
    criado_em: datetime
    relevancia: float


class BuscaDocumentosResposta(BaseModel):
    total: int
    pagina: int
    tamanho_pagina: int
    itens: list[DocumentoResumo]


# --------------------------------------------------------------------------
# Rota
# --------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/documentos", tags=["documentos"])

TAMANHO_PAGINA_MAXIMO = 100


@router.get("/busca", response_model=BuscaDocumentosResposta)
async def buscar_documentos(
    # Termo de busca (obrigatório). Aceita sintaxe "websearch": "frase exata", -excluir, OR.
    q: Annotated[str, Query(min_length=2, max_length=200, description="Termo de pesquisa")],
    # Filtros opcionais e combináveis (lógica AND entre filtros diferentes).
    tipo: Annotated[
        Optional[list[TipoDocumento]],
        Query(description="Um ou mais tipos (ex.: ?tipo=contrato&tipo=proposta)"),
    ] = None,
    autor_id: Annotated[Optional[uuid.UUID], Query(description="ID do autor")] = None,
    data_inicio: Annotated[Optional[date], Query(description="Criado a partir de (inclusivo)")] = None,
    data_fim: Annotated[Optional[date], Query(description="Criado até (inclusivo)")] = None,
    # Paginação
    pagina: Annotated[int, Query(ge=1, le=10_000)] = 1,
    tamanho_pagina: Annotated[int, Query(ge=1, le=TAMANHO_PAGINA_MAXIMO)] = 20,
    # Dependências
    session: AsyncSession = Depends(get_session),  # noqa: F821
    usuario: "CurrentUser" = Depends(get_current_user),  # noqa: F821
) -> BuscaDocumentosResposta:
    q = q.strip()
    if len(q) < 2:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Termo de busca muito curto.")

    if data_inicio and data_fim and data_inicio > data_fim:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "data_inicio não pode ser posterior a data_fim.",
        )

    # websearch_to_tsquery nunca lança erro de sintaxe com entrada de usuário.
    tsquery = func.websearch_to_tsquery("portuguese", q)

    # ---- Filtros obrigatórios: isolamento de tenant + não excluídos + match textual
    condicoes = [
        Documento.tenant_id == usuario.tenant_id,  # <- isolamento entre empresas
        Documento.excluido_em.is_(None),
        Documento.busca.op("@@")(tsquery),
    ]

    # ---- Filtros opcionais
    if tipo:
        condicoes.append(Documento.tipo.in_(tipo))

    if autor_id:
        # Já restrito ao tenant acima: um autor de outra empresa simplesmente não retorna nada.
        condicoes.append(Documento.autor_id == autor_id)

    if data_inicio:
        inicio = datetime.combine(data_inicio, time.min, tzinfo=timezone.utc)
        condicoes.append(Documento.criado_em >= inicio)

    if data_fim:
        # Limite superior exclusivo no dia seguinte, para incluir o dia final inteiro.
        fim = datetime.combine(data_fim + timedelta(days=1), time.min, tzinfo=timezone.utc)
        condicoes.append(Documento.criado_em < fim)

    # ---- Total
    total = await session.scalar(select(func.count()).select_from(Documento).where(*condicoes))
    total = total or 0

    # ---- Página de resultados, ordenada por relevância e depois por data
    relevancia = func.ts_rank_cd(Documento.busca, tsquery).label("relevancia")
    consulta = (
        select(
            Documento.id,
            Documento.titulo,
            Documento.tipo,
            Documento.autor_id,
            Documento.criado_em,
            relevancia,
        )
        .where(*condicoes)
        .order_by(relevancia.desc(), Documento.criado_em.desc(), Documento.id)
        .limit(tamanho_pagina)
        .offset((pagina - 1) * tamanho_pagina)
    )
    linhas = (await session.execute(consulta)).all()

    return BuscaDocumentosResposta(
        total=total,
        pagina=pagina,
        tamanho_pagina=tamanho_pagina,
        itens=[DocumentoResumo.model_validate(l, from_attributes=True) for l in linhas],
    )