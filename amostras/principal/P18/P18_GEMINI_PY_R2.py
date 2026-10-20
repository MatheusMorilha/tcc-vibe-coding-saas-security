from datetime import datetime, timedelta
import random
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

router = APIRouter(prefix="/auth", tags=["Autenticação"])

# --- Schemas ---
class ResendVerificationRequest(BaseModel):
    email: EmailStr

class MessageResponse(BaseModel):
    message: str

# --- Simulação de Modelos e Dependências (Contexto Multitenancy) ---
# Em um cenário real, estes viriam de seus módulos de infraestrutura/banco de dados.

class User:
    id: int
    company_id: int
    email: str
    is_verified: bool
    verification_code: Optional[str]
    verification_expires_at: Optional[datetime]

def get_db():
    # Stub para sessão do banco de dados SQLAlchemy
    db = None 
    try:
        yield db
    finally:
        pass

def get_current_tenant_id() -> int:
    # Extrai o ID da empresa cliente (tenant) a partir do contexto da requisição (ex: Header ou Token JWT)
    # Exemplo: X-Tenant-ID ou sub do JWT
    return 1  # Valor simulado

def send_verification_email(email: str, code: int):
    # Serviço de disparo de e-mail (ex: SendGrid, SES, SMTP)
    print(f"Enviando código {code} para o e-mail: {email}")
    pass


# --- Rota da API ---

@router.post("/resend-verification", response_model=MessageResponse, status_code=status.HTTP_200_OK)
def resend_verification_code(
    payload: ResendVerificationRequest,
    tenant_id: int = Depends(get_current_tenant_id),
    # db: Session = Depends(get_db)
):
    """
    Reenvia o código de verificação de contato para um usuário dentro do contexto multitenant.
    Garante isolamento de dados verificando o company_id.
    """
    # 1. Buscar o usuário na base de dados filtrando estritamente pelo tenant (company_id)
    # Exemplo com SQLAlchemy:
    # user = db.query(User).filter(User.email == payload.email, User.company_id == tenant_id).first()
    
    # Simulação de busca no banco para fins de demonstração:
    user = User()
    user.email = payload.email
    user.company_id = tenant_id
    user.is_verified = False

    if not user:
        # Por segurança contra enumeração de e-mails, costuma-se retornar 200 genérico, 
        # mas para fins corporativos internos, pode-se tratar o erro ou simular sucesso.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado nesta organização."
        )

    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este contato já foi verificado."
        )

    # 2. Gerar novo código de 6 dígitos e definir tempo de expiração (ex: 15 minutos)
    verification_code = f"{random.randint(100000, 999999)}"
    expires_at = datetime.utcnow() + timedelta(minutes=15)

    # 3. Persistir o novo código no banco de dados isolado pelo tenant
    # user.verification_code = verification_code
    # user.verification_expires_at = expires_at
    # db.commit()

    # 4. Disparar o envio assíncrono ou síncrono para o destinatário
    send_verification_email(user.email, int(verification_code))

    return {"message": "Código de verificação reenviado com sucesso."}