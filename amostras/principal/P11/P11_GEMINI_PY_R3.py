import secrets
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Boolean
from sqlalchemy.orm import Session, declarative_base

# Configuração base do ORM (exemplo simplificado)
Base = declarative_base()

class IntegrationKeyModel(Base):
    __tablename__ = "integration_keys"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, index=True, nullable=False)  # Isola os dados na base compartilhada
    key_hash = Column(String(255), unique=True, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

# Schemas de resposta Pydantic
class IntegrationKeyResponse(BaseModel):
    integration_key: str
    created_at: datetime
    message: str

    class Config:
        from_attributes = True

router = APIRouter(prefix="/api/v1/integrations", tags=["Integrations"])

@router.post(
    "/keys",
    response_model=IntegrationKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Gera uma nova chave de integração para a empresa cliente"
)
def generate_integration_key(
    # current_user: User = Depends(get_current_active_user), # Extrai o contexto do tenant autenticado
    db: Session = Depends(get_db) # Injeção de dependência da sessão do banco de dados
):
    # Simulação do tenant_id obtido através do usuário logado na requisição
    # Em produção: company_id = current_user.company_id
    company_id = 1042  

    # Gera uma chave criptografualmente segura com prefixo identificador
    raw_key = f"sk_live_{secrets.token_urlsafe(32)}"
    
    # Boas práticas de segurança: Armazenar o hash da chave no banco em vez da chave em texto plano
    # (Para fins didáticos, armazenamos o valor gerado diretamente, mas o ideal é aplicar hash SHA-256)
    db_integration_key = IntegrationKeyModel(
        company_id=company_id,
        key_hash=raw_key, 
        is_active=True
    )

    try:
        db.add(db_integration_key)
        db.commit()
        db.refresh(db_integration_key)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao persistir a chave de integração na base de dados."
        )

    # A chave em texto plano é retornada apenas neste momento e nunca mais poderá ser recuperada
    return {
        "integration_key": raw_key,
        "created_at": db_integration_key.created_at,
        "message": "Chave gerada com sucesso. Armazene-a em local seguro, pois ela não será exibida novamente."
    }