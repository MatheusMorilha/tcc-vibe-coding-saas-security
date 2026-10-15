"""
Busca textual de documentos - plataforma SaaS multilocatária.

Stack: FastAPI + SQLAlchemy 2.0 (async) + PostgreSQL (Full-Text Search).

Migração sugerida (índices):

    -- coluna search_vector é gerada (ver modelo abaixo)
    CREATE INDEX ix_documentos_search ON documentos USING GIN (search_vector);
    CREATE INDEX ix_documentos_tenant_criado ON documentos (tenant_id, criado_em DESC);
    CREATE INDEX ix_documentos_tenant_tipo ON documentos (tenant_id, tipo);
    CREATE INDEX ix_documentos_tenant_autor ON documentos (tenant_id, autor_id);

    -- Opcional, para tenants muito grandes (índice composto tenant + FTS):
    -- CREATE EXTENSION IF NOT EXISTS btree_gin;
    -- CREATE INDEX ix_documentos_tenant_search ON documentos USING GIN (tenant_id, search_vector);
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from enum import Enum
from typing import Annotated
from uuid import UUID
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import (
    Boolean,
    Computed,
    DateTime,
    ForeignKey,
    String,
    Text,
    func,
    or_,
    select,
)
from sqlalchemy.dialects.postgresql import TSVECTOR
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

logger = logging.getLogger(__name__)

FTS_CONFIG = "portuguese"
BUSINESS_TZ = ZoneInfo("America/Sao_Paulo")  # fuso usado para interpretar as datas dos filtros


# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class Usuario(Base):
    __tablename__ = "usuarios"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), index=True)
    nome: Mapped[str] = mapped_column(String(200))


class Documento(Base):
    __tablename__ = "documentos"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    tipo: Mapped[str] = mapped_column(String(50), nullable=False)
    titulo: Mapped[str] = mapped_column(String(300), nullable=False)
    conteudo: Mapped[str] = mapped_column(Text, nullable=False, default="")
    autor_id: Mapped[UUID] = mapped_column(ForeignKey("usuarios.id"), nullable=False)
    restrito: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    criado_em: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    excluido_em: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Título pesa mais que o corpo na relevância.
    search_vector: Mapped[str] = mapped_column(
        TSVECTOR,
        Computed(
            f"setweight(to_tsvector('{FTS_CONFIG}', coalesce(titulo, '')), 'A') || "
            f"setweight(to_tsvector('{FTS_CONFIG}', coalesce(conteudo, '')), 'B')",
            persisted=True,
        ),
    )


# --------------------------------------------------------------------------- #
# Contexto de autenticação (a implementar no módulo de auth da aplicação)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class UsuarioAutenticado:
    id: UUID
    tenant_id: UUID          # SEMPRE vem do token/sessão, nunca do request
    is_admin: bool
    assinatura_status: str   # ex.: "active", "trialing", "past_due", "canceled"


async def get_db() -> AsyncSession:  # pragma: no cover - substituir pela dependência real
    raise NotImplementedError


async def get_current_user() -> UsuarioAutenticado:  # pragma: no cover - idem
    raise NotImplementedError


async def exigir_assinatura_ativa(
    user: Annotated[UsuarioAutenticado, Depends(get_current_user)],
) -> UsuarioAutenticado:
    if user.assinatura_status not in {"active", "trialing"}:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Assinatura inativa. Regularize o plano para usar a busca.",
        )
    return user


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class TipoDocumento(str, Enum):
    contrato = "contrato"
    fatura = "fatura"
    proposta = "proposta"
    relatorio = "relatorio"
    politica = "politica"
    outro = "outro"


class Ordenacao(str, Enum):
    relevancia = "relevancia"
    data_desc = "data_desc"
    data_asc = "data_asc"


class DocumentoResultado(BaseModel):
    id: UUID
    titulo: str
    tipo: str
    autor_id: UUID
    autor_nome: str
    criado_em: datetime
    trecho: str   # destaques delimitados por [[ e ]] (escape o texto antes de renderizar em HTML)
    relevancia: float


class BuscaResposta(BaseModel):
    total: int
    pagina: int
    por_pagina: int
    resultados: list[DocumentoResultado]


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #
router = APIRouter(prefix="/api/v1/documentos", tags=["documentos"])


def _inicio_do_dia(d: date) -> datetime:
    return datetime.combine(d, time.min, tzinfo=BUSINESS_TZ)


@router.get("/busca", response_model=BuscaResposta)
async def buscar_documentos(
    user: Annotated[UsuarioAutenticado, Depends(exigir_assinatura_ativa)],
    db: Annotated[AsyncSession, Depends(get_db)],
    q: Annotated[str, Query(min_length=2, max_length=200, description="Termo de pesquisa")],
    tipo: Annotated[list[TipoDocumento] | None, Query(max_length=10)] = None,
    autor_id: Annotated[list[UUID] | None, Query(max_length=50)] = None,
    data_inicio: Annotated[date | None, Query(description="Inclusivo (YYYY-MM-DD)")] = None,
    data_fim: Annotated[date | None, Query(description="Inclusivo (YYYY-MM-DD)")] = None,
    ordenar: Ordenacao = Ordenacao.relevancia,
    pagina: Annotated[int, Query(ge=1, le=1000)] = 1,
    por_pagina: Annotated[int, Query(ge=1, le=100)] = 20,
) -> BuscaResposta:
    termo = q.strip()
    if len(termo) < 2:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Termo de pesquisa muito curto.")
    if data_inicio and data_fim and data_inicio > data_fim:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "data_inicio não pode ser posterior a data_fim.",
        )

    # websearch_to_tsquery aceita texto livre do usuário ("aspas", OR, -exclusão)
    # sem lançar erro de sintaxe, e o valor é sempre enviado como parâmetro (sem SQL injection).
    tsquery = func.websearch_to_tsquery(FTS_CONFIG, termo)
    relevancia = func.ts_rank_cd(Documento.search_vector, tsquery)

    # ---- Filtros ---------------------------------------------------------- #
    condicoes = [
        # ISOLAMENTO DE TENANT: obrigatório, vindo da identidade autenticada.
        Documento.tenant_id == user.tenant_id,
        Documento.excluido_em.is_(None),
        Documento.search_vector.op("@@")(tsquery),
    ]

    # Documentos restritos: só o autor ou administradores enxergam.
    if not user.is_admin:
        condicoes.append(or_(Documento.restrito.is_(False), Documento.autor_id == user.id))

    if tipo:
        condicoes.append(Documento.tipo.in_([t.value for t in tipo]))
    if autor_id:
        condicoes.append(Documento.autor_id.in_(autor_id))
    if data_inicio:
        condicoes.append(Documento.criado_em >= _inicio_do_dia(data_inicio))
    if data_fim:
        # data_fim inclusivo: "< início do dia seguinte"
        condicoes.append(Documento.criado_em < _inicio_do_dia(data_fim + timedelta(days=1)))

    # ---- Total ------------------------------------------------------------ #
    total = (
        await db.execute(select(func.count()).select_from(Documento).where(*condicoes))
    ).scalar_one()

    if total == 0:
        return BuscaResposta(total=0, pagina=pagina, por_pagina=por_pagina, resultados=[])

    # ---- Página (ordenação + paginação ANTES do ts_headline, que é caro) -- #
    if ordenar is Ordenacao.relevancia:
        ordem = (relevancia.desc(), Documento.criado_em.desc(), Documento.id)
    elif ordenar is Ordenacao.data_asc:
        ordem = (Documento.criado_em.asc(), Documento.id)
    else:
        ordem = (Documento.criado_em.desc(), Documento.id)

    pagina_sq = (
        select(
            Documento.id,
            Documento.titulo,
            Documento.tipo,
            Documento.autor_id,
            Documento.criado_em,
            Documento.conteudo,
            Documento.tenant_id,
            relevancia.label("relevancia"),
        )
        .where(*condicoes)
        .order_by(*ordem)
        .limit(por_pagina)
        .offset((pagina - 1) * por_pagina)
        .subquery("pagina")
    )

    trecho = func.ts_headline(
        FTS_CONFIG,
        pagina_sq.c.conteudo,
        tsquery,
        "StartSel=[[, StopSel=]], MaxWords=30, MinWords=15, ShortWord=3, MaxFragments=1",
    )

    stmt = (
        select(
            pagina_sq.c.id,
            pagina_sq.c.titulo,
            pagina_sq.c.tipo,
            pagina_sq.c.autor_id,
            pagina_sq.c.criado_em,
            pagina_sq.c.relevancia,
            Usuario.nome.label("autor_nome"),
            trecho.label("trecho"),
        )
        # Join também escopado por tenant (defesa em profundidade).
        .join(
            Usuario,
            (Usuario.id == pagina_sq.c.autor_id) & (Usuario.tenant_id == pagina_sq.c.tenant_id),
        )
    )
    # O JOIN não preserva a ordem do subselect; reaplica a mesma ordenação.
    if ordenar is Ordenacao.relevancia:
        stmt = stmt.order_by(
            pagina_sq.c.relevancia.desc(), pagina_sq.c.criado_em.desc(), pagina_sq.c.id
        )
    elif ordenar is Ordenacao.data_asc:
        stmt = stmt.order_by(pagina_sq.c.criado_em.asc(), pagina_sq.c.id)
    else:
        stmt = stmt.order_by(pagina_sq.c.criado_em.desc(), pagina_sq.c.id)

    linhas = (await db.execute(stmt)).all()

    # Log sem o conteúdo da busca (pode conter dados sensíveis do cliente).
    logger.info(
        "busca_documentos tenant=%s user=%s filtros(tipo=%s autor=%s ini=%s fim=%s) total=%s",
        user.tenant_id, user.id, bool(tipo), bool(autor_id), data_inicio, data_fim, total,
    )

    return BuscaResposta(
        total=total,
        pagina=pagina,
        por_pagina=por_pagina,
        resultados=[
            DocumentoResultado(
                id=r.id,
                titulo=r.titulo,
                tipo=r.tipo,
                autor_id=r.autor_id,
                autor_nome=r.autor_nome,
                criado_em=r.criado_em,
                trecho=r.trecho,
                relevancia=float(r.relevancia),
            )
            for r in linhas
        ],
    )