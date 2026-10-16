from fastapi import FastAPI, Depends, HTTPException, status, Path
from sqlalchemy.orm import Session
from sqlalchemy import select, and_
from pydantic import BaseModel
from typing import Annotated
import uuid

# --- Schemas & Models (Simulação) ---

class UserContext(BaseModel):
    """Contexto do usuário autenticado vindo do Token JWT/Sessão"""
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    role: str  # e.g., "ADMIN", "MEMBER"

class DeleteUserResponse(BaseModel):
    message: str
    deleted_user_id: uuid.UUID


# --- Dependências de Autenticação e Autorização ---

def get_current_user_context() -> UserContext:
    """
    Simula a extração e validação do JWT token/sessão do usuário logado.
    Em produção, valida a assinatura do JWT e extrai os 'claims'.
    """
    # Exemplo mockado de contexto extraído com segurança
    return UserContext(
        user_id=uuid.UUID("a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"),
        tenant_id=uuid.UUID("11111111-2222-3333-4444-555555555555"),
        role="ADMIN"
    )

def get_db():
    """Provedor de sessão do banco de dados (SQLAlchemy)"""
    db = Session()
    try:
        yield db
    finally:
        db.close()


# --- Definição do Endpoint ---

app = FastAPI(title="SaaS Tenant API")


@app.delete(
    "/api/v1/users/{user_id_to_delete}",
    response_model=DeleteUserResponse,
    status_code=status.HTTP_200_OK,
    summary="Remove permanentemente um usuário da organização")
async def delete_user(
    user_id_to_delete: Annotated[uuid.UUID, Path(description="UUID v4 do usuário a ser removido")],
    current_user: Annotated[UserContext, Depends(get_current_user_context)],
    db: Annotated[Session, Depends(get_db)]):
    """
    Remove permanentemente um usuário da base de dados garantindo isolamento multilocatário.
    """

    # 1. OWASP A01: Broken Access Control - Validação de Perfil (RBAC)
    if current_user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ação não permitida. Apenas administradores do locatário podem remover usuários."
        )

    # 2. Regra de Negócio/Segurança: Impede autoexclusão direta por esta rota
    if current_user.user_id == user_id_to_delete:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O administrador não pode remover a si mesmo por esta rota."
        )

    # 3. OWASP A01: Tenant Isolation / Prevenção de IDOR
    # A consulta DEVE incluir explicitamente o tenant_id do usuário autenticado.
    # Nunca confie apenas no ID do recurso vindo na URL.

    # Importação lazy do Model para fins de exemplo
    from models import User

    stmt = select(User).where(
        and_(
            User.id == user_id_to_delete,
            User.tenant_id == current_user.tenant_id  # Cláusula de Isolamento Crítica
        )
    )

    user_to_delete = db.execute(stmt).scalar_one_or_none()

    # 4. Trata o caso onde o usuário não existe OU pertence a outro Tenant
    # Para evitar enumeração/vazamento de dados de outros tenants, retornamos 404 genérico.
    if not user_to_delete:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado na sua organização."
        )

    # 5. Remoção Física (Hard Delete)
    try:
        db.delete(user_to_delete)
        db.commit()
    except Exception as e:
        db.rollback()
        # OWASP A09: Security Logging and Monitoring Failures / A05: Security Misconfiguration
        # Trata erro de integridade/FK sem expor detalhes internos do banco para o cliente
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha ao remover o usuário devido a restrições de integridade de dados."
        )

    return DeleteUserResponse(
        message="Usuário removido com sucesso.",
        deleted_user_id=user_id_to_delete
    )