"""
Rota GET /clientes — lista clientes da empresa autenticada, com filtro por nome.

Dependências: fastapi, sqlalchemy>=2.0, pyjwt, pydantic>=2
"""
import os
from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Index, String, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# --------------------------------------------------------------------------- #
# Modelo
# --------------------------------------------------------------------------- #


class Base(DeclarativeBase):
    pass


class Cliente(Base):
    __tablename__ = "clientes"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Coluna discriminadora do tenant: obrigatória em TODAS as tabelas de negócio.
    empresa_id: Mapped[int] = mapped_column(nullable=False, index=True)
    nome: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str | None] = mapped_column(String(254))
    telefone: Mapped[str | None] = mapped_column(String(30))

    # Índice composto: o filtro por tenant sempre vem primeiro.
    __table_args__ = (Index("ix_clientes_empresa_nome", "empresa_id", "nome"),)


# --------------------------------------------------------------------------- #
# Schemas de resposta (expõe apenas o necessário; empresa_id não vaza)
# --------------------------------------------------------------------------- #


class ClienteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    nome: str
    email: str | None = None
    telefone: str | None = None


class ClientesPage(BaseModel):
    total: int
    pagina: int
    limite: int
    itens: list[ClienteOut]


# --------------------------------------------------------------------------- #
# Infraestrutura: sessão de banco e autenticação
# --------------------------------------------------------------------------- #


def get_db():
    """Substitua pela sua fábrica de sessões (SessionLocal)."""
    from app.database import SessionLocal  # ajuste ao seu projeto

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class UsuarioAutenticado(BaseModel):
    id: int
    empresa_id: int


_bearer = HTTPBearer(auto_error=True)
_JWT_SECRET = os.environ["JWT_SECRET"]  # falha cedo se não estiver configurado
_JWT_ALG = "HS256"


def get_usuario_atual(
    cred: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
) -> UsuarioAutenticado:
    """Valida o JWT e extrai usuário e empresa dos claims assinados."""
    try:
        payload = jwt.decode(
            cred.credentials,
            _JWT_SECRET,
            algorithms=[_JWT_ALG],
            options={"require": ["exp", "sub", "empresa_id"]},
        )
        return UsuarioAutenticado(id=int(payload["sub"]), empresa_id=int(payload["empresa_id"]))
    except (jwt.PyJWTError, ValueError, KeyError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #

router = APIRouter(prefix="/clientes", tags=["Clientes"])


def _escapar_like(termo: str) -> str:
    """Neutraliza curingas do LIKE para que '%' e '_' sejam tratados como texto."""
    return termo.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")


@router.get("", response_model=ClientesPage)
def listar_clientes(
    usuario: Annotated[UsuarioAutenticado, Depends(get_usuario_atual)],
    db: Annotated[Session, Depends(get_db)],
    nome: Annotated[
        str | None,
        Query(min_length=1, max_length=100, description="Filtra por parte do nome (sem diferenciar maiúsculas)."),
    ] = None,
    pagina: Annotated[int, Query(ge=1)] = 1,
    limite: Annotated[int, Query(ge=1, le=100)] = 20,
) -> ClientesPage:
    # 1) Isolamento de tenant: sempre a empresa do token, jamais um parâmetro do cliente.
    filtros = [Cliente.empresa_id == usuario.empresa_id]

    # 2) Filtro opcional por nome (parametrizado pelo SQLAlchemy -> sem SQL injection).
    if nome and nome.strip():
        padrao = f"%{_escapar_like(nome.strip())}%"
        filtros.append(Cliente.nome.ilike(padrao, escape="\\"))

    # 3) Total para paginação (mesmos filtros).
    total = db.scalar(select(func.count()).select_from(Cliente).where(*filtros)) or 0

    # 4) Página de resultados, com ordenação estável (nome + id).
    itens = db.scalars(
        select(Cliente)
        .where(*filtros)
        .order_by(Cliente.nome, Cliente.id)
        .offset((pagina - 1) * limite)
        .limit(limite)
    ).all()

    return ClientesPage(total=total, pagina=pagina, limite=limite, itens=itens)