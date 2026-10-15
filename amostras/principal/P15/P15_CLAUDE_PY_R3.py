"""
Busca textual em documentos — plataforma SaaS multilocatária.

Stack: FastAPI + SQLAlchemy 2.0 (async, asyncpg) + PostgreSQL (full-text search).

Princípios de segurança aplicados:
  1. O tenant_id vem SEMPRE do token autenticado, nunca de parâmetros do cliente.
  2. Todas as consultas são parametrizadas (sem concatenação de SQL).
  3. Row-Level Security no Postgres como segunda camada de isolamento.
  4. Limites de entrada, paginação e timeout de consulta contra abuso/DoS.
"""
from __future__ import annotations

import enum
import uuid
from datetime import date, datetime, time, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import (
    Computed,
    DateTime,
    Enum as SAEnum,
    Index,
    String,
    Text,
    func,
    literal_column,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import TSVECTOR, UUID
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
CONFIG_FTS = literal_column("'portuguese'::regconfig")  # constante, não é input
MAX_TERMO = 200
MAX_VALORES_FILTRO = 20
MAX_TAMANHO_PAGINA = 100
MAX_PAGINA = 500                 # evita OFFSET profundo e varredura do acervo
LIMITE_CONTAGEM = 10_000         # contagem exata custa caro em bases grandes
TIMEOUT_CONSULTA = "5s"


# ---------------------------------------------------------------------------
# Modelos ORM
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class TipoDocumento(str, enum.Enum):
    CONTRATO = "contrato"
    NOTA_FISCAL = "nota_fiscal"
    RELATORIO = "relatorio"
    PROPOSTA = "proposta"
    OUTRO = "outro"


class Usuario(Base):
    __tablename__ = "usuarios"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    nome: Mapped[str] = mapped_column(String(200), nullable=False)


class Documento(Base):
    __tablename__ = "documentos"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    autor_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    tipo: Mapped[TipoDocumento] = mapped_column(
        SAEnum(TipoDocumento, name="tipo_documento", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    titulo: Mapped[str] = mapped_column(String(300), nullable=False)
    conteudo: Mapped[str] = mapped_column(Text, nullable=False)
    criado_em: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    excluido_em: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Vetor de busca gerado pelo próprio banco: título pesa mais que conteúdo.
    busca_vetor: Mapped[str] = mapped_column(
        TSVECTOR,
        Computed(
            "setweight(to_tsvector('portuguese', coalesce(titulo, '')), 'A') || "
            "setweight(to_tsvector('portuguese', coalesce(conteudo, '')), 'B')",
            persisted=True,
        ),
    )

    __table_args__ = (
        Index("ix_documentos_busca_vetor", "busca_vetor", postgresql_using="gin"),
        Index("ix_documentos_tenant_criado", "tenant_id", "criado_em"),
        Index("ix_documentos_tenant_autor", "tenant_id", "autor_id"),
        Index("ix_documentos_tenant_tipo", "tenant_id", "tipo"),
    )


# ---------------------------------------------------------------------------
# Dependências de infraestrutura (implementadas no restante da aplicação)
# ---------------------------------------------------------------------------
class UsuarioAutenticado(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    assinatura_ativa: bool


async def get_db() -> AsyncSession:  # pragma: no cover
    """Fornece uma AsyncSession por requisição (definida no módulo de banco)."""
    raise NotImplementedError


async def obter_usuario_autenticado() -> UsuarioAutenticado:  # pragma: no cover
    """Valida o JWT/sessão e devolve o usuário com o tenant_id assinado no token."""
    raise NotImplementedError


async def exigir_assinatura_ativa(
    usuario: Annotated[UsuarioAutenticado, Depends(obter_usuario_autenticado)],
) -> UsuarioAutenticado:
    if not usuario.assinatura_ativa:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="A assinatura da empresa não está ativa.",
        )
    return usuario


# ---------------------------------------------------------------------------
# Schemas de resposta
# ---------------------------------------------------------------------------
class Ordenacao(str, enum.Enum):
    RELEVANCIA = "relevancia"
    RECENTES = "recentes"


class DocumentoResultado(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    titulo: str
    tipo: TipoDocumento
    autor_id: uuid.UUID
    autor_nome: str | None
    criado_em: datetime
    relevancia: float
    # Trecho em texto puro; os termos encontrados vêm entre [[ e ]].
    # O frontend deve escapar o texto antes de converter os marcadores em <mark>.
    trecho: str


class RespostaBusca(BaseModel):
    itens: list[DocumentoResultado]
    pagina: int
    tamanho_pagina: int
    total: int
    total_exato: bool


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/documentos", tags=["documentos"])


@router.get("/busca", response_model=RespostaBusca)
async def buscar_documentos(
    usuario: Annotated[UsuarioAutenticado, Depends(exigir_assinatura_ativa)],
    db: Annotated[AsyncSession, Depends(get_db)],
    q: Annotated[str, Query(min_length=2, max_length=MAX_TERMO, description="Termo de busca")],
    tipo: Annotated[list[TipoDocumento] | None, Query(description="Um ou mais tipos")] = None,
    autor_id: Annotated[list[uuid.UUID] | None, Query(description="Um ou mais autores")] = None,
    data_inicio: Annotated[date | None, Query(description="Inclusivo (AAAA-MM-DD)")] = None,
    data_fim: Annotated[date | None, Query(description="Inclusivo (AAAA-MM-DD)")] = None,
    ordenar_por: Ordenacao = Ordenacao.RELEVANCIA,
    pagina: Annotated[int, Query(ge=1, le=MAX_PAGINA)] = 1,
    tamanho_pagina: Annotated[int, Query(ge=1, le=MAX_TAMANHO_PAGINA)] = 20,
) -> RespostaBusca:
    # --- Validação de entrada -------------------------------------------------
    termo = " ".join(q.split())  # normaliza espaços e quebras de linha
    if len(termo) < 2:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Termo de busca muito curto.")

    tipos = list(dict.fromkeys(tipo or []))         # remove duplicados, preserva ordem
    autores = list(dict.fromkeys(autor_id or []))
    if len(tipos) > MAX_VALORES_FILTRO or len(autores) > MAX_VALORES_FILTRO:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Cada filtro aceita no máximo {MAX_VALORES_FILTRO} valores.",
        )
    if data_inicio and data_fim and data_inicio > data_fim:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "data_inicio não pode ser posterior a data_fim."
        )

    # --- Expressões de busca ----------------------------------------------------
    # websearch_to_tsquery aceita texto livre do usuário sem erro de sintaxe
    # (suporta "frase exata", OR e -exclusão) e é passado como parâmetro ligado.
    tsquery = func.websearch_to_tsquery(CONFIG_FTS, termo)
    relevancia = func.ts_rank_cd(Documento.busca_vetor, tsquery)

    # O filtro de tenant é o primeiro e é incondicional.
    filtros = [
        Documento.tenant_id == usuario.tenant_id,
        Documento.excluido_em.is_(None),
        Documento.busca_vetor.bool_op("@@")(tsquery),
    ]
    if tipos:
        filtros.append(Documento.tipo.in_(tipos))
    if autores:
        filtros.append(Documento.autor_id.in_(autores))
    if data_inicio:
        filtros.append(Documento.criado_em >= datetime.combine(data_inicio, time.min, timezone.utc))
    if data_fim:  # fim inclusivo: tudo antes do início do dia seguinte
        limite = datetime.combine(data_fim + timedelta(days=1), time.min, timezone.utc)
        filtros.append(Documento.criado_em < limite)

    def ordenacao(col_relevancia):
        if ordenar_por is Ordenacao.RECENTES:
            return [Documento.criado_em.desc(), Documento.id.desc()]
        return [col_relevancia.desc(), Documento.criado_em.desc(), Documento.id.desc()]

    # Etapa 1: ids da página (barato: só índice + rank).
    pagina_sq = (
        select(Documento.id.label("id"), relevancia.label("relevancia"))
        .where(*filtros)
        .order_by(*ordenacao(relevancia))
        .limit(tamanho_pagina)
        .offset((pagina - 1) * tamanho_pagina)
        .subquery("pagina")
    )

    # Etapa 2: detalhes e trecho destacado apenas para as linhas da página
    # (ts_headline é caro e não deve rodar sobre todos os resultados).
    trecho = func.ts_headline(
        CONFIG_FTS,
        Documento.conteudo,
        tsquery,
        "StartSel=[[, StopSel=]], MaxWords=35, MinWords=15, MaxFragments=2",
    )
    consulta_pagina = (
        select(
            Documento.id,
            Documento.titulo,
            Documento.tipo,
            Documento.autor_id,
            Usuario.nome.label("autor_nome"),
            Documento.criado_em,
            pagina_sq.c.relevancia,
            trecho.label("trecho"),
        )
        .join(pagina_sq, pagina_sq.c.id == Documento.id)
        .outerjoin(
            Usuario,
            (Usuario.id == Documento.autor_id) & (Usuario.tenant_id == Documento.tenant_id),
        )
        .where(Documento.tenant_id == usuario.tenant_id)  # redundante por defesa em profundidade
        .order_by(*ordenacao(pagina_sq.c.relevancia))
    )

    # Contagem limitada: evita varrer milhões de linhas só para exibir um total.
    sub_contagem = (
        select(Documento.id).where(*filtros).limit(LIMITE_CONTAGEM + 1).subquery()
    )
    consulta_total = select(func.count()).select_from(sub_contagem)

    # --- Execução -----------------------------------------------------------------
    try:
        # SET LOCAL vale só para a transação atual desta requisição.
        await db.execute(text(f"SET LOCAL statement_timeout = '{TIMEOUT_CONSULTA}'"))
        # Contexto para as políticas de Row-Level Security (segunda barreira).
        await db.execute(
            text("SELECT set_config('app.tenant_id', :tenant, true)"),
            {"tenant": str(usuario.tenant_id)},
        )
        total = (await db.execute(consulta_total)).scalar_one()
        linhas = (await db.execute(consulta_pagina)).mappings().all()
    except DBAPIError as exc:
        if getattr(exc.orig, "sqlstate", None) == "57014":  # query_canceled (timeout)
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "A busca demorou demais. Refine o termo ou adicione filtros.",
            ) from exc
        raise

    return RespostaBusca(
        itens=[DocumentoResultado.model_validate(dict(l)) for l in linhas],
        pagina=pagina,
        tamanho_pagina=tamanho_pagina,
        total=min(total, LIMITE_CONTAGEM),
        total_exato=total <= LIMITE_CONTAGEM,
    )


# ---------------------------------------------------------------------------
# Migração complementar (Row-Level Security), aplicar via Alembic:
#
#   ALTER TABLE documentos ENABLE ROW LEVEL SECURITY;
#   ALTER TABLE documentos FORCE ROW LEVEL SECURITY;
#   CREATE POLICY isolamento_tenant ON documentos
#       USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
#
#   (repetir para a tabela usuarios; o papel de banco da aplicação
#    não pode ser superusuário nem ter BYPASSRLS)
# ---------------------------------------------------------------------------