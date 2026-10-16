from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, constr
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Integer,
    Numeric,
    String,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# ==========================================
# MODELOS DE DOMÍNIO / BANCO DE DADOS
# ==========================================

class TipoDesconto(str, Enum):
    PERCENTUAL = "PERCENTUAL"
    VALOR_FIXO = "VALOR_FIXO"


class Assinatura(Base):
    __tablename__ = "assinaturas"

    id = Column(Integer, primary_key=True)
    empresa_id = Column(Integer, nullable=False, unique=True, index=True)
    valor_mensal_base = Column(Numeric(10, 2), nullable=False)
    valor_mensal_atual = Column(Numeric(10, 2), nullable=False)
    cupom_aplicado_id = Column(Integer, ForeignKey("cupons.id"), nullable=True)
    atualizado_em = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Cupom(Base):
    __tablename__ = "cupons"

    id = Column(Integer, primary_key=True)
    codigo = Column(String(50), nullable=False, unique=True, index=True)
    tipo_desconto = Column(SQLEnum(TipoDesconto), nullable=False)
    valor_desconto = Column(Numeric(10, 2), nullable=False)
    expira_em = Column(DateTime(timezone=True), nullable=True)
    usos_maximos = Column(Integer, nullable=True)
    usos_atuais = Column(Integer, default=0, nullable=False)
    ativo = Column(Boolean, default=True, nullable=False)


# ==========================================
# SCHEMAS (VALIDAÇÃO E TIPAGEM OWASP A03/A04)
# ==========================================

class ResgatarCupomRequest(BaseModel):
    # Regex estrito alfanumérico para mitigar payloads de injeção e abuso de entrada
    codigo_cupom: constr(strip_whitespace=True, to_upper=True, min_length=3, max_length=50, pattern=r"^[A-Z0-9_-]+$") = Field(
        ..., description="Código promocional a ser resgatado"
    )


class ResgatarCupomResponse(BaseModel):
    mensagem: str
    empresa_id: int
    cupom: str
    valor_base: Decimal
    desconto_aplicado: Decimal
    novo_valor_mensalidade: Decimal


class AuthenticatedUser(BaseModel):
    user_id: int
    empresa_id: int  # Isolamento multilocatário garantido pelo contexto de autenticação
    role: str


# ==========================================
# DEPENDÊNCIAS DE SESSÃO E AUTENTICAÇÃO
# ==========================================

async def get_db_session() -> AsyncSession:
    """Provedor de sessão assíncrona do banco de dados."""
    raise NotImplementedError("Injetado pelo container da aplicação")


async def get_current_user() -> AuthenticatedUser:
    """
    OWASP A01 / A07:
    Valida a assinatura do token JWT/OAuth2 e extrai os claims do locatário.
    """
    raise NotImplementedError("Injetado pelo middleware/dependência de segurança")


# ==========================================
# ROTA DE RESGATE DO CUPOM
# ==========================================

router = APIRouter(prefix="/api/v1/assinaturas", tags=["Assinaturas"])


@router.post(
    "/resgatar-cupom",
    response_model=ResgatarCupomResponse,
    status_code=status.HTTP_200_OK,
    summary="Resgata um cupom de desconto para a empresa autenticada",)
async def resgatar_cupom(
    payload: ResgatarCupomRequest,
    auth_user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],):
    # A01: Controle de autorização rígido - apenas administradores podem alterar faturamento
    if auth_user.role not in {"ADMIN", "FINANCEIRO"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permissão insuficiente para alterar dados de assinatura.",
        )

    agora = datetime.now(timezone.utc)

    # Início da transação com bloqueio pessimista para evitar concorrência/duplo resgate
    async with db.begin():
        # 1. Recupera o cupom com trava pessimista de linha (FOR UPDATE)
        query_cupom = (
            select(Cupom)
            .where(Cupom.codigo == payload.codigo_cupom, Cupom.ativo.is_(True))
            .with_for_update()
        )
        result_cupom = await db.execute(query_cupom)
        cupom = result_cupom.scalar_one_or_none()

        if not cupom:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cupom promocional inválido ou inexistente.",
            )

        # Validação temporal
        if cupom.expira_em and cupom.expira_em < agora:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Este cupom expirou.",
            )

        # Validação de cota de uso
        if cupom.usos_maximos is not None and cupom.usos_atuais >= cupom.usos_maximos:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="O limite de utilização deste cupom foi atingido.",
            )

        # 2. Busca e bloqueia a assinatura estritamente vinculada ao inquilino autenticado (OWASP BOLA)
        query_assinatura = (
            select(Assinatura)
            .where(Assinatura.empresa_id == auth_user.empresa_id)
            .with_for_update()
        )
        result_assinatura = await db.execute(query_assinatura)
        assinatura = result_assinatura.scalar_one_or_none()

        if not assinatura:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Assinatura não localizada para a empresa autenticada.",
            )

        # Validação de duplicidade de resgate
        if assinatura.cupom_aplicado_id == cupom.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Este cupom já está aplicado à sua assinatura.",
            )

        # 3. Cálculo financeiro determinístico utilizando Decimal
        valor_base = Decimal(str(assinatura.valor_mensal_base))
        taxa_ou_valor = Decimal(str(cupom.valor_desconto))

        if cupom.tipo_desconto == TipoDesconto.PERCENTUAL:
            if taxa_ou_valor > Decimal("100.00") or taxa_ou_valor <= Decimal("0.00"):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Inconsistência cadastral na porcentagem do cupom.",
                )
            desconto_efetivo = (valor_base * (taxa_ou_valor / Decimal("100.00"))).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
        else:  # VALOR_FIXO
            desconto_efetivo = min(taxa_ou_valor, valor_base)

        novo_valor = max(Decimal("0.00"), valor_base - desconto_efetivo).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )

        # 4. Atualização de estado
        cupom.usos_atuais += 1
        assinatura.cupom_aplicado_id = cupom.id
        assinatura.valor_mensal_atual = novo_valor
        assinatura.atualizado_em = agora

    return ResgatarCupomResponse(
        mensagem="Cupom aplicado com sucesso.",
        empresa_id=auth_user.empresa_id,
        cupom=cupom.codigo,
        valor_base=valor_base,
        desconto_aplicado=desconto_efetivo,
        novo_valor_mensalidade=novo_valor,
    )