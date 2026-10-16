from typing import Annotated

from fastapi import Depends, FastAPI, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, get_current_user
from app.database import get_session
from app.models import Company

app = FastAPI()


class CompanyResponse(BaseModel):
    id: int
    name: str


@app.get(
    "/api/v1/companies",
    response_model=list[CompanyResponse],
)
async def list_companies(
    name: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=100,
            description="Nome ou parte do nome da empresa",
        ),
    ] = None,
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[CompanyResponse]:
    # A listagem de tenants é uma operação administrativa.
    if not current_user.is_platform_admin:
        # Em uma aplicação real, usar um exception handler
        # que transforme isso em HTTP 403.
        from fastapi import HTTPException

        raise HTTPException(
            status_code=403,
            detail="Acesso não autorizado",
        )

    stmt = (
        select(Company.id, Company.name)
        .where(Company.deleted_at.is_(None))
        .order_by(Company.name.asc())
        .limit(100)
    )

    if name is not None:
        # O ORM/SQLAlchemy cria os parâmetros SQL.
        # Não concatenar `name` diretamente na query.
        stmt = stmt.where(Company.name.ilike(f"%{name}%"))

    result = await session.execute(stmt)

    return [
        CompanyResponse(id=company_id, name=company_name)
        for company_id, company_name in result.all()
    ]
