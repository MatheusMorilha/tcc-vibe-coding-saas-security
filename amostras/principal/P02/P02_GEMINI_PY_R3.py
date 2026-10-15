from datetime import date
from decimal import Decimal
from typing import Annotated, Optional
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

# ------------------------------------------------------------------------------
# Modelos Pydantic (Schemas de Entrada e Saída)
# ------------------------------------------------------------------------------

class TipoTransacao(str, Enum):
    RECEITA = "RECEITA"
    DESPESA = "DESPESA"

class StatusTransacao(str, Enum):
    PAGO = "PAGO"
    PENDENTE = "PENDENTE"
    CANCELADO = "CANCELADO"

class RelatorioFinanceiroResponse(BaseModel):
    empresa_id: int
    data_inicio: date
    data_fim: date
    total_receitas: Decimal = Field(default=Decimal("0.00"), description="Total de receitas pagas/recebidas")
    total_despesas: Decimal = Field(default=Decimal("0.00"), description="Total de despesas pagas")
    saldo_consolidado: Decimal = Field(default=Decimal("0.00"), description="Receitas - Despesas")
    receitas_pendentes: Decimal = Field(default=Decimal("0.00"), description="Receitas ainda não liquidadas")
    despesas_pendentes: Decimal = Field(default=Decimal("0.00"), description="Despesas ainda não liquidadas")
    quantidade_transacoes: int = 0

# Model simulado para representação do Usuário Autenticado
class UsuarioAutenticado(BaseModel):
    id: int
    empresa_id: int  # Tenant ID associado ao usuário no Token JWT
    is_admin: bool = False

# ------------------------------------------------------------------------------
# Dependências de Exemplo (Injeção do Banco e Autenticação)
# ------------------------------------------------------------------------------

async def get_db_session() -> AsyncSession:
    """Retorna uma sessão assíncrona do banco de dados (SQLAlchemy)."""
    # Substituir pela implementação real do gerador de sessões
    pass

async def get_usuario_atual() -> UsuarioAutenticado:
    """Extrai o usuário autenticado do token JWT da requisição."""
    # Substituir pela validação real do token JWT
    pass

# ------------------------------------------------------------------------------
# Definição do Router
# ------------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/relatorios", tags=["Financeiro"])

@router.get(
    "/empresas/{empresa_id}/financeiro",
    response_model=RelatorioFinanceiroResponse,
    status_code=status.HTTP_200_OK,
    summary="Gera relatório financeiro consolidado do tenant")
async def gerar_relatorio_financeiro(
    empresa_id: int,
    data_inicio: Annotated[date, Query(description="Data inicial do período (AAAA-MM-DD)")],
    data_fim: Annotated[date, Query(description="Data final do período (AAAA-MM-DD)")],
    db: AsyncSession = Depends(get_db_session),
    usuario: UsuarioAutenticado = Depends(get_usuario_atual)):
    """
    Gera um relatório financeiro consolidado para uma empresa específica em um período.

    **Garantias de Segurança SaaS (Multitenancy):**
    - Garante que o usuário autenticado só possa visualizar dados da própria empresa.
    - Aplica o filtro de `empresa_id` em todas as agregações no banco de dados.
    """

    # 1. Validação do Período
    if data_inicio > data_fim:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A data inicial não pode ser posterior à data final."
        )

    # 2. Segurança SaaS (Isolamento de Tenants)
    # Impede que o usuário de um tenant acesse dados de outro alterando o ID na URL
    if usuario.empresa_id != empresa_id and not usuario.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: Você não possui permissão para acessar os dados desta empresa."
        )

    # Importação do model SQLAlchemy de transações (exemplo)
    from app.models import TransacaoModel

    # 3. Consulta Agregada Direta no Banco de Dados (Performance O(1) de memória na API)
    stmt = (
        select(
            func.coalesce(
                func.sum(TransacaoModel.valor).filter(
                    and_(
                        TransacaoModel.tipo == TipoTransacao.RECEITA,
                        TransacaoModel.status == StatusTransacao.PAGO
                    )
                ), 0
            ).label("total_receitas"),

            func.coalesce(
                func.sum(TransacaoModel.valor).filter(
                    and_(
                        TransacaoModel.tipo == TipoTransacao.DESPESA,
                        TransacaoModel.status == StatusTransacao.PAGO
                    )
                ), 0
            ).label("total_despesas"),

            func.coalesce(
                func.sum(TransacaoModel.valor).filter(
                    and_(
                        TransacaoModel.tipo == TipoTransacao.RECEITA,
                        TransacaoModel.status == StatusTransacao.PENDENTE
                    )
                ), 0
            ).label("receitas_pendentes"),

            func.coalesce(
                func.sum(TransacaoModel.valor).filter(
                    and_(
                        TransacaoModel.tipo == TipoTransacao.DESPESA,
                        TransacaoModel.status == StatusTransacao.PENDENTE
                    )
                ), 0
            ).label("despesas_pendentes"),

            func.count(TransacaoModel.id).label("total_transacoes")
        )
        .where(
            and_(
                TransacaoModel.empresa_id == empresa_id,  # Isolamento por tenant
                TransacaoModel.data_competencia >= data_inicio,
                TransacaoModel.data_competencia <= data_fim,
                TransacaoModel.status != StatusTransacao.CANCELADO
            )
        )
    )

    resultado = await db.execute(stmt)
    dados = resultado.one()

    # 4. Cálculo do Saldo Líquido Consolidado
    total_receitas = Decimal(str(dados.total_receitas))
    total_despesas = Decimal(str(dados.total_despesas))
    saldo_consolidado = total_receitas - total_despesas

    # 5. Montagem do Payload de Resposta
    return RelatorioFinanceiroResponse(
        empresa_id=empresa_id,
        data_inicio=data_inicio,
        data_fim=data_fim,
        total_receitas=total_receitas,
        total_despesas=total_despesas,
        saldo_consolidado=saldo_consolidado,
        receitas_pendentes=Decimal(str(dados.receitas_pendentes)),
        despesas_pendentes=Decimal(str(dados.despesas_pendentes)),
        quantidade_transacoes=dados.total_transacoes
    )