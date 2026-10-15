from fastapi import FastAPI, Depends, HTTPException, Query
from sqlalchemy import asc, desc, select
from sqlalchemy.orm import Session

app = FastAPI()


ALLOWED_SORT_COLUMNS = {
    "id": Contract.id,
    "name": Contract.name,
    "created_at": Contract.created_at,
    "expires_at": Contract.expires_at,
}


@app.get("/contracts")
def list_contracts(
    sort_by: str = Query("created_at"),
    direction: str = Query("desc"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    sort_column = ALLOWED_SORT_COLUMNS.get(sort_by)

    if sort_column is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid sort column",
        )

    if direction not in {"asc", "desc"}:
        raise HTTPException(
            status_code=400,
            detail="Invalid sort direction",
        )

    order_expression = (
        asc(sort_column)
        if direction == "asc"
        else desc(sort_column)
    )

    query = (
        select(Contract)
        .where(Contract.tenant_id == current_user.tenant_id)
        .order_by(order_expression)
    )

    contracts = db.execute(query).scalars().all()

    return {
        "data": contracts,
        "sort_by": sort_by,
        "direction": direction,
    }
