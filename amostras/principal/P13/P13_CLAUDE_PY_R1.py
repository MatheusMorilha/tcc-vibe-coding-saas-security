from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import ForeignKey, String, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# ---------------------------------------------------------------------------
# Modelos (simplificados)
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class Cliente(Base):
    __tablename__ = "clientes"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Coluna de tenant: indexada, pois TODA consulta filtra por ela.
    empresa_id: Mapped[int] = mapped_column(
        ForeignKey("empresas.id"), index=True, nullable=False
    )
    nome: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(255))
    telefone: Mapped[str | None] = mapped_column(String(32))


class UsuarioAutenticado(BaseModel):
    """Identidade extraída do token validado (JWT/sessão), nunca do cliente."""

    id: int
    empresa_id: int
    assinatura_ativa: bool


# ---------------------------------------------------------------------------
# Schemas de resposta (não expõem empresa_id nem campos internos)
# ---------------------------------------------------------------------------


class ClienteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    nome: str
    email: str | None = None
    telefone: str | None = None


class ClientesPage(BaseModel):
    total: int
    limit: int
    offset: int
    itens: list[ClienteOut]


# ---------------------------------------------------------------------------
# Dependências (implementações reais ficam na camada de infraestrutura)
# ---------------------------------------------------------------------------


def get_db() -> Session:  # pragma: no cover
    """Fornece a sessão do banco (ex.: sessionmaker + yield/close)."""
    raise NotImplementedError


def get_usuario_atual() -> UsuarioAutenticado:  # pragma: no cover
    """Valida o token e retorna o usuário com o empresa_id dele."""
    raise NotImplementedError


def exigir_assinatura_ativa(
    usuario: Annotated[UsuarioAutenticado, Depends(get_usuario_atual)],
) -> UsuarioAutenticado:
    if not usuario.assinatura_ativa:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Assinatura inativa.",
        )
    return usuario


# ---------------------------------------------------------------------------
# Utilitário
# ---------------------------------------------------------------------------


def escapar_like(valor: str, escape: str = "\\") -> str:
    """Neutraliza curingas do LIKE para que '%' e '_' sejam tratados como texto."""
    return (
        valor.replace(escape, escape * 2)
        .replace("%", escape + "%")
        .replace("_", escape + "_")
    )


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/clientes", tags=["clientes"])


@router.get("", response_model=ClientesPage)
def listar_clientes(
    usuario: Annotated[UsuarioAutenticado, Depends(exigir_assinatura_ativa)],
    db: Annotated[Session, Depends(get_db)],
    nome: Annotated[
        str | None,
        Query(min_length=1, max_length=100, description="Filtro por nome (contém)"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ClientesPage:
    # 1) Isolamento de tenant: sempre aplicado, vindo da identidade autenticada.
    filtros = [Cliente.empresa_id == usuario.empresa_id]

    # 2) Filtro opcional por nome: parametrizado (sem SQL injection),
    #    case-insensitive e com curingas escapados.
    if nome:
        termo = nome.strip()
        if termo:
            filtros.append(
                Cliente.nome.ilike(f"%{escapar_like(termo)}%", escape="\\")
            )

    total = db.scalar(select(func.count()).select_from(Cliente).where(*filtros)) or 0

    itens = db.scalars(
        select(Cliente)
        .where(*filtros)
        .order_by(Cliente.nome, Cliente.id)  # ordenação estável para paginação
        .limit(limit)
        .offset(offset)
    ).all()

    return ClientesPage(total=total, limit=limit, offset=offset, itens=itens)