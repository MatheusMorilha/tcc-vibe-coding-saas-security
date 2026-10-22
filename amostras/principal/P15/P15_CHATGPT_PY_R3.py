from datetime import date, datetime, time, timedelta, timezone
from typing import Generator
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
)
from pydantic import BaseModel, ConfigDict
from sqlalchemy import (
    DateTime,
    ForeignKey,
    String,
    Text,
    Uuid,
    create_engine,
    func,
    select,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)
from sqlalchemy.dialects.postgresql import TSVECTOR


# --------------------------------------------------
# Configuração do banco de dados
# --------------------------------------------------

DATABASE_URL = "postgresql+psycopg://user:password@localhost/saas"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --------------------------------------------------
# Modelos
# --------------------------------------------------

class Document(Base):
    __tablename__ = "documents"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True
    )
    tenant_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), index=True, nullable=False
    )
    author_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    document_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


# --------------------------------------------------
# Identidade autenticada
# --------------------------------------------------

class CurrentUser(BaseModel):
    id: UUID
    tenant_id: UUID


def get_current_user() -> CurrentUser:
    """
    Substitua pela dependência real de autenticação:
    validação do token, identificação do usuário e
    resolução do tenant no servidor.

    Nunca obtenha tenant_id de um parâmetro controlado
    livremente pelo cliente.
    """
    raise HTTPException(
        status_code=401,
        detail="Autenticação necessária",
    )


def require_active_subscription(
    user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CurrentUser:
    """
    Integre aqui a verificação da assinatura ativa
    do tenant, consultando a tabela de assinaturas.
    """
    # Exemplo: consultar a assinatura vinculada a user.tenant_id.
    # Se não estiver ativa, lançar HTTPException(403, ...).
    return user


# --------------------------------------------------
# Resposta da API
# --------------------------------------------------

class DocumentResult(BaseModel):
    id: UUID
    title: str
    document_type: str
    author_id: UUID
    created_at: datetime
    relevance: float

    model_config = ConfigDict(from_attributes=True)


class DocumentSearchResponse(BaseModel):
    items: list[DocumentResult]
    page: int
    page_size: int
    total: int


# --------------------------------------------------
# Rota de busca textual
# --------------------------------------------------

router = APIRouter(prefix="/documents", tags=["Documents"])


@router.get("/search", response_model=DocumentSearchResponse)
def search_documents(
    q: str = Query(..., min_length=2, max_length=200),
    document_type: str | None = Query(
        default=None, alias="type", max_length=50
    ),
    author_id: UUID | None = Query(default=None),
    start_date: date | None = Query(default=None),
    end_date: date | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    user: CurrentUser = Depends(require_active_subscription),
    db: Session = Depends(get_db),
) -> DocumentSearchResponse:

    # Validações dos filtros
    if start_date and end_date and start_date > end_date:
        raise HTTPException(
            status_code=422,
            detail="start_date não pode ser posterior a end_date",
        )

    term = q.strip()
    if len(term) < 2:
        raise HTTPException(
            status_code=422,
            detail="O termo de busca deve conter pelo menos 2 caracteres",
        )

    # Busca textual nativa do PostgreSQL em português.
    searchable_text = func.to_tsvector(
        "portuguese",
        func.concat(
            Document.title,
            " ",
            Document.content,
        ),
    )

    search_query = func.plainto_tsquery("portuguese", term)

    relevance = func.ts_rank(
        searchable_text,
        search_query,
    ).label("relevance")

    # REGRA CRÍTICA: o tenant é sempre aplicado.
    # O cliente não pode remover nem substituir esse filtro.
    conditions = [
        Document.tenant_id == user.tenant_id,
        searchable_text.op("@@")(search_query),
    ]

    # Os filtros opcionais são combinados com AND.
    if document_type:
        conditions.append(
            Document.document_type == document_type
        )

    if author_id:
        conditions.append(Document.author_id == author_id)

    if start_date:
        start_datetime = datetime.combine(
            start_date, time.min, tzinfo=timezone.utc
        )
        conditions.append(
            Document.created_at >= start_datetime
        )

    if end_date:
        # Limite exclusivo: inclui todo o dia final.
        end_datetime = datetime.combine(
            end_date + timedelta(days=1),
            time.min,
            tzinfo=timezone.utc,
        )
        conditions.append(
            Document.created_at < end_datetime
        )

    # Total de resultados antes da paginação.
    count_stmt = (
        select(func.count())
        .select_from(Document)
        .where(*conditions)
    )
    total = db.scalar(count_stmt) or 0

    # Resultados ordenados por relevância e data.
    offset = (page - 1) * page_size

    stmt = (
        select(Document, relevance)
        .where(*conditions)
        .order_by(
            relevance.desc(),
            Document.created_at.desc(),
        )
        .offset(offset)
        .limit(page_size)
    )

    rows = db.execute(stmt).all()

    items = [
        DocumentResult(
            id=document.id,
            title=document.title,
            document_type=document.document_type,
            author_id=document.author_id,
            created_at=document.created_at,
            relevance=float(score or 0),
        )
        for document, score in rows
    ]

    return DocumentSearchResponse(
        items=items,
        page=page,
        page_size=page_size,
        total=total,
    )