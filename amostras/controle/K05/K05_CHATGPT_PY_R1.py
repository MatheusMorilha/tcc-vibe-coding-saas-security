from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import String, select
from sqlalchemy.ext.asyncio import AsyncSession

# Imaginários no exemplo:
# - get_db(): fornece uma AsyncSession
# - get_current_user(): autentica o usuário
# - User.is_platform_admin: indica permissão para listar tenants
# - Company: modelo ORM da empresa


app = FastAPI()


class CompanyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


async def get_db() -> AsyncSession:
    """
    Substitua pela implementação real da sessão do banco.
    """
    raise NotImplementedError


async def get_current_user():
    """
    Substitua pela implementação real de autenticação/autorização.
    """
    raise NotImplementedError


class Company:
    id: int
    name: str


@app.get(
    "/api/v1/companies",
    response_model=list[CompanyResponse],
    status_code=status.HTTP_200_OK,
)
async def list_companies(
    name: Optional[str] = Query(
        default=None,
        min_length=1,
        max_length=100,
        description="Parte do nome da empresa usada para filtrar os resultados.",
    ),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    # Controle de autorização: somente administradores da plataforma
    # podem consultar o cadastro global de empresas.
    if not current_user.is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso não autorizado.",
        )

    stmt = select(Company)

    if name is not None:
        # SQLAlchemy cria um parâmetro vinculado, evitando concatenação
        # direta do valor recebido na query SQL.
        normalized_name = name.strip()

        if not normalized_name:
            return []

        stmt = stmt.where(
            Company.name.ilike(f"%{normalized_name}%")
        )

    # Limite defensivo para evitar respostas excessivamente grandes.
    stmt = stmt.limit(100)

    result = await db.execute(stmt)
    companies = result.scalars().all()

    return companies
