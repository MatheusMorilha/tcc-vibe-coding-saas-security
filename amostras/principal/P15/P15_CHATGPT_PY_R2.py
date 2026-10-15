from datetime import date
from typing import Optional

from fastapi import FastAPI, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.orm import Session

app = FastAPI()


class Document(BaseModel):
    id: int
    tenant_id: int
    title: str
    content: str
    document_type: str
    author_id: int
    created_at: date


def get_db():
    # Retorne aqui uma sessão SQLAlchemy.
    ...


def get_current_tenant_id() -> int:
    # Deve vir do usuário autenticado, nunca de um parâmetro enviado
    # pelo cliente.
    ...


@app.get("/api/documents/search")
def search_documents(
    q: str = Query(..., min_length=1),
    document_type: Optional[str] = None,
    author_id: Optional[int] = None,
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    filters = [
        Document.tenant_id == tenant_id,
        Document.content.ilike(f"%{q}%"),
    ]

    if document_type:
        filters.append(Document.document_type == document_type)

    if author_id:
        filters.append(Document.author_id == author_id)

    if date_from:
        filters.append(Document.created_at >= date_from)

    if date_to:
        filters.append(Document.created_at <= date_to)

    query = (
        select(Document)
        .where(and_(*filters))
        .order_by(Document.created_at.desc())
    )

    return db.scalars(query).all()
