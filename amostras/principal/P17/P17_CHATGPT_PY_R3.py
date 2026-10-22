from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_current_user
from app.models import Despesa, Usuario, Empresa

router = APIRouter(prefix="/despesas", tags=["Despesas"])


class AprovacaoResponse(BaseModel):
    mensagem: str
    despesa_id: int
    status: Literal["aprovada"]
    aprovada_por: int
    aprovada_em: datetime


@router.post(
    "/{despesa_id}/aprovar",
    response_model=AprovacaoResponse,
    status_code=status.HTTP_200_OK,
)
def aprovar_despesa(
    despesa_id: int,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(get_current_user),
):
    # 1. Verifica se o usuário pertence a uma empresa válida.
    empresa = db.get(Empresa, usuario.empresa_id)

    if empresa is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Empresa não encontrada ou acesso não autorizado.",
        )

    # 2. Verifica se o usuário tem permissão para aprovar despesas.
    if not usuario.pode_aprovar_despesas:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para aprovar despesas.",
        )

    # 3. Busca a despesa dentro do contexto da empresa.
    # O bloqueio de linha reduz o risco de aprovações concorrentes.
    try:
        despesa = db.execute(
            select(Despesa)
            .where(
                Despesa.id == despesa_id,
                Despesa.empresa_id == usuario.empresa_id,
            )
            .with_for_update()
        ).scalar_one_or_none()

        if despesa is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Solicitação de despesa não encontrada.",
            )

        # 4. Impede aprovar uma solicitação em estado inválido.
        if despesa.status != "pendente":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A solicitação não está pendente de aprovação.",
            )

        # 5. Registra a aprovação e os dados de auditoria.
        agora = datetime.now(timezone.utc)

        despesa.status = "aprovada"
        despesa.aprovada_por = usuario.id
        despesa.aprovada_em = agora

        db.commit()
        db.refresh(despesa)

        # 6. Retorna a confirmação da operação.
        return AprovacaoResponse(
            mensagem="Solicitação de despesa aprovada com sucesso.",
            despesa_id=despesa.id,
            status="aprovada",
            aprovada_por=usuario.id,
            aprovada_em=despesa.aprovada_em,
        )

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível aprovar a solicitação.",
        )