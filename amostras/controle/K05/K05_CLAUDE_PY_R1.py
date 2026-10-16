"""
GET /api/v1/clientes?nome=<texto>&pagina=1&tamanho=20

Lista os clientes DA EMPRESA do usuário autenticado, com filtro opcional por nome.

Dependências: fastapi, sqlalchemy>=2.0, pydantic>=2, pyjwt
Segredos (chave JWT, DSN do banco) devem vir de variáveis de ambiente / cofre.
"""
import logging
import os
from datetime import datetime, timezone
from typing import Annotated, Optional

import jwt  # PyJWT
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict
from sqlalchemy import DateTime, ForeignKey, Integer, String, Boolean, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("api.clientes")

# --------------------------------------------------------------------------
# Modelos (simplificados)
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class Empresa(Base):
    __tablename__ = "empresas"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assinatura_ativa: Mapped[bool] = mapped_column(Boolean, default=False)


class Usuario(Base):
    __tablename__ = "usuarios"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    empresa_id: Mapped[int] = mapped_column(ForeignKey("empresas.id"), index=True)
    ativo: Mapped[bool] = mapped_column(Boolean, default=True)
    # Permissões do usuário, ex.: "clientes:read" (pode vir de tabela de papéis)
    permissoes: Mapped[str] = mapped_column(String(500), default="")


class Cliente(Base):
    __tablename__ = "clientes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    empresa_id: Mapped[int] = mapped_column(ForeignKey("empresas.id"), index=True)
    nome: Mapped[str] = mapped_column(String(200), index=True)
    email: Mapped[Optional[str]] = mapped_column(String(254))
    criado_em: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    # Campos sensíveis (CPF/CNPJ, endereço etc.) existem no modelo,
    # mas NÃO são expostos no schema de resposta.


# --------------------------------------------------------------------------
# Schemas de resposta (allowlist de campos -> evita exposição excessiva de dados)
# --------------------------------------------------------------------------
class ClienteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    nome: str
    email: Optional[str] = None
    criado_em: datetime


class PaginaClientes(BaseModel):
    itens: list[ClienteOut]
    pagina: int
    tamanho: int
    total: int


# --------------------------------------------------------------------------
# Infra: sessão de banco (stub) e autenticação
# --------------------------------------------------------------------------
def get_db() -> Session:  # pragma: no cover - implementar com seu engine/sessionmaker
    """Deve entregar uma Session; a conexão usa usuário de banco com privilégio mínimo."""
    raise NotImplementedError


JWT_PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]
JWT_ISSUER = os.environ["JWT_ISSUER"]
JWT_AUDIENCE = os.environ["JWT_AUDIENCE"]

bearer = HTTPBearer(auto_error=False)


def _nao_autenticado() -> HTTPException:
    # Mensagem genérica: não revela o motivo exato da falha (A07)
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não autenticado.",
        headers={"WWW-Authenticate": "Bearer"},
    )


class Contexto(BaseModel):
    usuario_id: int
    empresa_id: int  # SEMPRE derivado do servidor, nunca de parâmetro da requisição


def get_contexto(
    cred: Annotated[Optional[HTTPAuthorizationCredentials], Depends(bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> Contexto:
    if cred is None:
        raise _nao_autenticado()

    try:
        claims = jwt.decode(
            cred.credentials,
            JWT_PUBLIC_KEY,
            algorithms=["RS256"],          # algoritmo fixo: bloqueia "alg: none"/confusão de algoritmo
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )
        usuario_id = int(claims["sub"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise _nao_autenticado()

    # Revalida no banco: usuário ativo, empresa vigente e assinatura ativa.
    # O tenant vem do banco, não do token nem da requisição.
    usuario = db.get(Usuario, usuario_id)
    if usuario is None or not usuario.ativo:
        raise _nao_autenticado()

    empresa = db.get(Empresa, usuario.empresa_id)
    if empresa is None or not empresa.assinatura_ativa:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso negado.")

    if "clientes:read" not in usuario.permissoes.split(","):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso negado.")

    return Contexto(usuario_id=usuario.id, empresa_id=usuario.empresa_id)


# --------------------------------------------------------------------------
# Utilitários
# --------------------------------------------------------------------------
def _escapar_like(texto: str, escape: str = "\\") -> str:
    """Neutraliza curingas do LIKE (% e _) para o termo ser tratado como texto literal."""
    return (
        texto.replace(escape, escape + escape)
        .replace("%", escape + "%")
        .replace("_", escape + "_")
    )


# --------------------------------------------------------------------------
# Rota
# --------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1", tags=["clientes"])


@router.get("/clientes", response_model=PaginaClientes)
def listar_clientes(
    response: Response,
    ctx: Annotated[Contexto, Depends(get_contexto)],
    db: Annotated[Session, Depends(get_db)],
    # Validação de entrada com allowlist: letras (unicode), dígitos, espaço, . ' -
    nome: Annotated[
        Optional[str],
        Query(min_length=1, max_length=100, pattern=r"^[\w .'\-]+$"),
    ] = None,
    pagina: Annotated[int, Query(ge=1, le=10_000)] = 1,
    tamanho: Annotated[int, Query(ge=1, le=100)] = 20,  # teto evita extração em massa/DoS
) -> PaginaClientes:
    # Filtro de tenant OBRIGATÓRIO e sempre presente (A01 - Broken Access Control)
    filtros = [Cliente.empresa_id == ctx.empresa_id]

    if nome:
        termo = _escapar_like(nome.strip())
        # ORM gera query parametrizada (A03 - Injection); sem concatenação de SQL
        filtros.append(Cliente.nome.ilike(f"%{termo}%", escape="\\"))

    try:
        total = db.scalar(select(func.count()).select_from(Cliente).where(*filtros)) or 0

        itens = db.scalars(
            select(Cliente)
            .where(*filtros)
            .order_by(Cliente.nome, Cliente.id)   # ordenação determinística p/ paginação estável
            .limit(tamanho)
            .offset((pagina - 1) * tamanho)
        ).all()
    except Exception:
        # Log interno detalhado; resposta ao cliente genérica (A05/A09)
        logger.exception("Falha ao listar clientes", extra={"empresa_id": ctx.empresa_id})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno.",
        )

    # Log de auditoria sem dados pessoais (não registra o termo de busca em texto)
    logger.info(
        "clientes_listados",
        extra={
            "usuario_id": ctx.usuario_id,
            "empresa_id": ctx.empresa_id,
            "filtrou_por_nome": bool(nome),
            "qtd": len(itens),
            "ts": datetime.now(timezone.utc).isoformat(),
        },
    )

    # Dados de clientes não devem ser cacheados por proxies/navegadores
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"

    return PaginaClientes(
        itens=[ClienteOut.model_validate(c) for c in itens],
        pagina=pagina,
        tamanho=tamanho,
        total=total,
    )