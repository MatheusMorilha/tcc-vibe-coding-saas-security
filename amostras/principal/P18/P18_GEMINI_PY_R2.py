import random
import string
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.orm import Session

# ==============================================================================
# 1. SCHEMAS (Pydantic)
# ==============================================================================

class ResendVerificationRequest(BaseModel):
    email: EmailStr
    tenant_id: str  # Em contextos autenticados, pode vir do token JWT/contexto da requisição

class APIResponse(BaseModel):
    message: str


# ==============================================================================
# 2. MODELOS DE DADOS (SQLAlchemy Mock/Structure)
# ==============================================================================

# Representação conceitual das entidades no banco de dados multilocatário:
#
# class User(Base):
#     __tablename__ = "users"
#     id = Column(String, primary_key=True)
#     tenant_id = Column(String, index=True, nullable=False) # Isolamento por locatário
#     email = Column(String, nullable=False)
#     is_verified = Column(Boolean, default=False)
#     verification_code = Column(String, nullable=True)
#     code_expires_at = Column(DateTime(timezone=True), nullable=True)
#     last_code_sent_at = Column(DateTime(timezone=True), nullable=True)


# ==============================================================================
# 3. SERVIÇOS AUXILIARES
# ==============================================================================

def generate_verification_code(length: int = 6) -> str:
    """Gera um código numérico de 6 dígitos."""
    return ''.join(random.choices(string.digits, k=length))

def send_verification_email(email: str, code: str, tenant_id: str) -> None:
    """
    Interface para o serviço de envio de e-mails/SMS (ex: AWS SES, SendGrid, Twilio).
    Em produção, execute este disparo em background (Task Queue/Celery/BackgroundTasks).
    """
    # Lógica de integração com provedor transacional de e-mail
    pass


# ==============================================================================
# 4. ROTA DA API (FastAPI)
# ==============================================================================

router = APIRouter(prefix="/auth", tags=["Autenticação"])

# Configurações de política de reenvio
COOLDOWN_SECONDS = 60         # Tempo mínimo entre solicitações (Rate Limit)
EXPIRATION_MINUTES = 15       # Validade do código gerado

@router.post(
    "/resend-verification-code",
    response_model=APIResponse,
    status_code=status.HTTP_200_OK,
    summary="Reenvia o código de verificação para confirmação de contato")
async def resend_verification_code(
    payload: ResendVerificationRequest,
    db: Session = Depends(get_db_session)  # Injeção da sessão do banco de dados):
    now = datetime.now(timezone.utc)

    # 1. Busca o usuário garantindo o isolamento multilocatário (tenant_id + email)
    query = select(User).where(
        User.tenant_id == payload.tenant_id,
        User.email == payload.email
    )
    user = db.execute(query).scalar_one_or_none()

    # 2. Resposta genérica contra User Enumeration Attack:
    # Se o usuário não existir ou já estiver verificado, retornamos a mesma mensagem genérica.
    generic_success_message = "Se as informações coincidirem com uma conta pendente de verificação, um novo código será enviado."

    if not user or user.is_verified:
        return APIResponse(message=generic_success_message)

    # 3. Aplicação de Cooldown (Rate Limiting por usuário)
    if user.last_code_sent_at:
        elapsed_seconds = (now - user.last_code_sent_at).total_seconds()
        if elapsed_seconds < COOLDOWN_SECONDS:
            retry_after = int(COOLDOWN_SECONDS - elapsed_seconds)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Aguarde {retry_after} segundos antes de solicitar um novo código."
            )

    # 4. Geração do novo código e atualização dos timestamps
    new_code = generate_verification_code()

    user.verification_code = new_code
    user.code_expires_at = now + timedelta(minutes=EXPIRATION_MINUTES)
    user.last_code_sent_at = now

    db.add(user)
    db.commit()

    # 5. Disparo do envio do e-mail
    send_verification_email(
        email=user.email,
        code=new_code,
        tenant_id=user.tenant_id
    )

    return APIResponse(message=generic_success_message)