from datetime import date
from typing import Optional

from fastapi import FastAPI, Depends, Query
from sqlalchemy import select, or_
from sqlalchemy.orm import Session

app = FastAPI()


@app.get("/api/documents/search")
def search_documents(
    term: str = Query(..., min_length=1),
    document_type: Optional[str] = Query(None),
    author_id: Optional[int] = Query(None),
    date_from: Optional[date] = Query(None),
    date_to: Optional[date] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # O tenant vem exclusivamente do usuário autenticado.
    tenant_id = current_user.tenant_id

    stmt = select(Document).where(
        Document.tenant_id == tenant_id,
        or_(
            Document.title.ilike(f"%{term}%"),
            Document.content.ilike(f"%{term}%"),
        ),
    )

    if document_type is not None:
        stmt = stmt.where(Document.type == document_type)

    if author_id is not None:
        stmt = stmt.where(Document.author_id == author_id)

    if date_from is not None:
        stmt = stmt.where(Document.created_at >= date_from)

    if date_to is not None:
        stmt = stmt.where(Document.created_at < date_to)

    stmt = stmt.order_by(Document.created_at.desc())

    return db.execute(stmt).scalars().all()
