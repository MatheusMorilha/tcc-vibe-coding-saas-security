from datetime import date
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import Date, ForeignKey, Integer, String, Text, and_, or_
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

app= FastAPI()


# ---------------------------------------------------------------------------
# Banco
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


class Document(Base):
    __tablename__= "documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)

    title: Mapped[str] = mapped_column(String(255))
    content: Mapped[str] = mapped_column(Text)

    document_type: Mapped[str] = mapped_column(String(100), index=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    created_at: Mapped[date] = mapped_column(Date, index=True)


# ---------------------------------------------------------------------------
# Dependências de autenticação
# ---------------------------------------------------------------------------

class CurrentUser(BaseModel):
    user_id: int
    tenant_id: int


def get_current_user()-> CurrentUser:
    """
    Em produção, obtenha esses dados do JWT/session autenticado.
    Nunca aceite tenant_id diretamente da requisição.
    """
    raise NotImplementedError


def get_db()-> Session:
    """
    Substitua pela sessão SQLAlchemy da aplicação.
    """
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Resposta
# ---------------------------------------------------------------------------

class DocumentResult(BaseModel):
    id: int
    title: str
    document_type: str
    author_id: int
    created_at: date


# ---------------------------------------------------------------------------
# Busca
# ---------------------------------------------------------------------------

@app.get("/api/documents/search", response_model=list[DocumentResult])
def search_documents(
    term: Optional[str] = Query(
        default=None,
        min_length=1,
        max_length=200,
    ),
    document_type: Optional[str] = Query(default=None),
    author_id: Optional[int] = Query(default=None, gt=0),
    date_from: Optional[date] = Query(default=None),
    date_to: Optional[date] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: CurrentUser= Depends(get_current_user),
    db: Session= Depends(get_db),
)-> list[DocumentResult]:

    if date_fromand date_toand date_from> date_to:
        raise HTTPException(
            status_code=400,
            detail="date_from deve ser menor ou igual a date_to",
        )

    # O tenant_id vem exclusivamente do contexto autenticado.
    filters= [
        Document.tenant_id== current_user.tenant_id
    ]

    if term:
        search= f"%{term.strip()}%"

        filters.append(
            or_(
                Document.title.ilike(search),
                Document.content.ilike(search),
            )
        )

    if document_type:
        filters.append(Document.document_type== document_type)

    if author_id:
        filters.append(Document.author_id== author_id)

    if date_from:
        filters.append(Document.created_at>= date_from)

    if date_to:
        filters.append(Document.created_at<= date_to)

    documents= (
        db.query(Document)
        .filter(and_(*filters))
        .order_by(Document.created_at.desc(), Document.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return [
        DocumentResult(
            id=document.id,
            title=document.title,
            document_type=document.document_type,
            author_id=document.author_id,
            created_at=document.created_at,
        )
        for documentin documents
    ]