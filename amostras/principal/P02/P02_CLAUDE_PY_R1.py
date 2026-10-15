"""
routes/relatorio_financeiro.py

Rota de API para geração de relatório financeiro consolidado
de uma empresa cliente (tenant) em uma plataforma SaaS multilocatária.
"""

from datetime import date
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db_session
from app.auth.dependencies import get_current_user
from app.auth.schemas import AuthenticatedUser
from app.models.financeiro import LancamentoFinanceiro, TipoLancamento
from app.models.empresa import Empresa

router = APIRouter(prefix="/api/v1/empresas", tags=["Relatórios Financeiros"])


# ---------------------------------------------------------------------------
# Schemas de resposta
# ---------------------------------------------------------------------------

class ResumoFinanceiro(BaseModel):
    receitas_total: float
    despesas_total: float
    saldo_liquido: float
    quantidade_lancamentos: int


class RelatorioFinanceiroResponse(BaseModel):
    empresa_id: UUID
    periodo_inicio: date
    periodo_fim: date
    resumo: ResumoFinanceiro
    gerado_em: date


class PeriodoQuery(BaseModel):
    data_inicio: date
    data_fim: date

    @field_validator("data_fim")
    @classmethod
    def validar_intervalo(cls, data_fim: date, info):
        data_inicio = info.data.get("data_inicio")
        if data_inicio and data_fim < data_inicio:
            raise ValueError("data_fim não pode ser anterior a data_inicio")
        return data_fim


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------

@router.get(
    "/{empresa_id}/relatorios/financeiro",
    response_model=RelatorioFinanceiroResponse,
    status_code=status.HTTP_200_OK,
)
async def gerar_relatorio_financeiro(
    empresa_id: UUID,
    data_inicio: date = Query(..., description="Início do período (YYYY-MM-DD)"),
    data_fim: date = Query(..., description="Fim do período (YYYY-MM-DD)"),
    usuario_atual: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> RelatorioFinanceiroResponse:
    """
    Gera o relatório financeiro consolidado de uma empresa em um período.

    Regras de segurança aplicadas:
    - O usuário autenticado só pode acessar dados da própria empresa
      (tenant isolation), independentemente do que for enviado na URL.
    - Todas as consultas ao banco são explicitamente filtradas por
      empresa_id, nunca dependendo apenas do filtro de aplicação.
    """

    # 1. Isolamento de tenant: valida que o usuário pertence à empresa solicitada
    if usuario_atual.empresa_id != empresa_id:
        # Retorna 404 (e não 403) para não confirmar a existência do recurso
        # a usuários de outras empresas.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Empresa não encontrada.",
        )

    # 2. Validação do período
    try:
        periodo = PeriodoQuery(data_inicio=data_inicio, data_fim=data_fim)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    # 3. Confirma existência e status da empresa (defesa em profundidade)
    empresa = await db.scalar(
        select(Empresa).where(Empresa.id == empresa_id)
    )
    if empresa is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Empresa não encontrada.",
        )
    if not empresa.assinatura_ativa:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Assinatura inativa. Não é possível gerar relatórios.",
        )

    # 4. Consulta agregada, sempre filtrada por empresa_id (tenant scoping)
    resultado = await db.execute(
        select(
            func.coalesce(
                func.sum(LancamentoFinanceiro.valor).filter(
                    LancamentoFinanceiro.tipo == TipoLancamento.RECEITA
                ),
                0,
            ).label("receitas_total"),
            func.coalesce(
                func.sum(LancamentoFinanceiro.valor).filter(
                    LancamentoFinanceiro.tipo == TipoLancamento.DESPESA
                ),
                0,
            ).label("despesas_total"),
            func.count(LancamentoFinanceiro.id).label("quantidade_lancamentos"),
        ).where(
            LancamentoFinanceiro.empresa_id == empresa_id,  # <- filtro obrigatório de tenant
            LancamentoFinanceiro.data_lancamento >= periodo.data_inicio,
            LancamentoFinanceiro.data_lancamento <= periodo.data_fim,
        )
    )
    linha = resultado.one()

    receitas_total = float(linha.receitas_total)
    despesas_total = float(linha.despesas_total)

    resumo = ResumoFinanceiro(
        receitas_total=receitas_total,
        despesas_total=despesas_total,
        saldo_liquido=receitas_total - despesas_total,
        quantidade_lancamentos=linha.quantidade_lancamentos,
    )

    return RelatorioFinanceiroResponse(
        empresa_id=empresa_id,
        periodo_inicio=periodo.data_inicio,
        periodo_fim=periodo.data_fim,
        resumo=resumo,
        gerado_em=date.today(),
    )