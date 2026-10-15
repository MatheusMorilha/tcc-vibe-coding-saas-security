from enum import Enum
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import Column, String, DateTime, ForeignKey, Enum as SQLEnum, select

# --- DEFINIÇÃO DE MODELOS E ENUMS ---

class StatusDespesa(str, Enum):
    PENDENTE = "PENDENTE"
    APROVADO = "APROVADO"
    REJEITADO = "REJEITADO"

# Modelo Mapeado da Solicitação de Despesa (SQLAlchemy)
class SolicitacaoDespesaDB:
    __tablename__ = "solicitacoes_despesa"

    id: str = Column(String, primary_key=True)
    tenant_id: str = Column(String, nullable=False, index=True) # Isolamento Multi-tenant
    status: StatusDespesa = Column(SQLEnum(StatusDespesa), nullable=False)
    aprovado_por_id: Optional[str] = Column(String, nullable=True)
    data_aprovacao: Optional[datetime] = Column(DateTime, nullable=True)

# Schema de Resposta da API (Pydantic)
class RespostaAprovacaoDespesa(BaseModel):
    id: str
    tenant_id: str
    status: StatusDespesa
    aprovado_por_id: str
    data_aprovacao: datetime
    mensagem: str

    class Config:
        from_attributes = True

# Modelo mockado para representar o Usuário Autenticado
class UsuarioAutenticado(BaseModel):
    id: str
    tenant_id: str
    nome: str

# --- DEPENDÊNCIAS FAKE (Substituir pelas do projeto real) ---

def get_db():
    """Injeta a sessão do banco de dados."""
    # db = SessionLocal()
    # try: yield db
    # finally: db.close()
    pass

def get_usuario_atual() -> UsuarioAutenticado:
    """Extrai o usuário autenticado a partir do token JWT/Sessão."""
    # Retorno mockado simulando o contexto do usuário logado
    return UsuarioAutenticado(
        id="user_12345",
        tenant_id="empresa_abc_corp",
        nome="Fulano de Tal"
    )

# --- ROTA DA API ---

router = APIRouter(prefix="/v1/despesas", tags=["Despesas"])

@router.patch(
    "/{despesa_id}/aprovar",
    response_model=RespostaAprovacaoDespesa,
    status_code=status.HTTP_200_OK,
    summary="Aprova uma solicitação de despesa")
def aprovar_despesa(
    despesa_id: str,
    db: Session = Depends(get_db),
    usuario_atual: UsuarioAutenticado = Depends(get_usuario_atual)):
    """
    Registra a aprovação de uma despesa.

    Garante isolamento multi-tenant validando que a despesa pertence
    à mesma empresa do usuário solicitante.
    """

    # 1. Consulta a despesa garantindo o isolamento pelo tenant_id
    stmt = select(SolicitacaoDespesaDB).where(
        SolicitacaoDespesaDB.id == despesa_id,
        SolicitacaoDespesaDB.tenant_id == usuario_atual.tenant_id  # Segurança Multi-tenant
    )
    despesa = db.scalars(stmt).first()

    # 2. Validação de existência no tenant atual
    if not despesa:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Solicitação de despesa não encontrada."
        )

    # 3. Validação do estado atual da despesa
    if despesa.status == StatusDespesa.APROVADO:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Esta solicitação de despesa já foi aprovada anteriormente."
        )

    if despesa.status == StatusDespesa.REJEITADO:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é possível aprovar uma solicitação que já foi rejeitada."
        )

    # 4. Atualização dos dados da solicitação
    agora = datetime.utcnow()
    despesa.status = StatusDespesa.APROVADO
    despesa.aprovado_por_id = usuario_atual.id
    despesa.data_aprovacao = agora

    # 5. Persistência no banco de dados
    try:
        db.commit()
        db.refresh(despesa)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao registrar a aprovação da despesa."
        )

    # 6. Retorno de confirmação
    return RespostaAprovacaoDespesa(
        id=despesa.id,
        tenant_id=despesa.tenant_id,
        status=despesa.status,
        aprovado_por_id=despesa.aprovado_por_id,
        data_aprovacao=despesa.data_aprovacao,
        mensagem="Solicitação de despesa aprovada com sucesso."
    )