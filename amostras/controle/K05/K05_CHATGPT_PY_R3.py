from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import String, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

app = FastAPI()


# ---------------------------------------------------------------------------
# Banco
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)


async def get_db() -> AsyncSession:
    """
    Retorne aqui uma sessão criada pelo pool da aplicação.

    Exemplo conceitual:
        async with async_session_factory() as session:
            yield session
    """
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Autenticação/autorização
# ---------------------------------------------------------------------------

class CurrentUser(BaseModel):
    id: int
    is_platform_admin: bool


async def get_current_user() -> CurrentUser:
    """
    Deve validar o token/sessão da requisição e retornar o usuário autenticado.

    Não confie em IDs, roles ou tenant_id enviados pelo cliente.
    """
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Resposta
# ---------------------------------------------------------------------------

class CustomerResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------

@app.get(
    "/api/v1/customers",
    response_model=list[CustomerResponse],
)
async def list_customers(
    name: Annotated[
        str | None,
        Query(
            default=None,
            min_length=1,
            max_length=150,
            description="Parte do nome do cliente usada para filtrar a busca.",
        ),
    ] = None,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[CustomerResponse]:

    # Somente usuários autorizados podem consultar clientes.
    if not current_user.is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso não autorizado.",
        )

    stmt = select(Customer)

    if name is not None:
        # SQLAlchemy gera uma consulta parametrizada.
        # Não concatenamos o valor recebido diretamente no SQL.
        stmt = stmt.where(Customer.name.ilike(f"%{name}%"))

    stmt = stmt.order_by(Customer.name).limit(100)

    result = await db.execute(stmt)
    customers = result.scalars().all()

    return list(customers)
