from datetime import datetime, timedelta
import secrets
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from sqlalchemy.orm import Session

router = APIRouter(prefix="/auth", tags=["Autenticação"])

# Configuração de hash de senha
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Configurações de token (ex: expira em 15 minutos)
TOKEN_EXPIRE_MINUTES = 15

# ==========================================
# SCHEMAS (Pydantic)
# ==========================================

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str = Field(..., description="Token seguro enviado por e-mail")
    new_password: str = Field(..., min_length=8, description="Nova senha do usuário")

# ==========================================
# SERVIÇOS AUXILIARES (Simulados)
# ==========================================

def send_reset_email(to_email: str, reset_token: str):
    """
    Simula o envio de e-mail com o link de redefinição contendo o token.
    Em produção, utilize serviços como SendGrid, AWS SES, Resend, etc.
    """
    reset_link = f"https://app.seudominio.com/reset-password?token={reset_token}"
    print(f"[EMAIL SERVICE] Enviando para {to_email}: Acesse o link para redefinir sua senha: {reset_link}")

# ==========================================
# ROTAS DA API
# ==========================================

@router.post("/forgot-password", status_code=status.HTTP_200_OK)
def forgot_password(payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """
    Recebe o e-mail do usuário, gera um token de recuperação seguro
    e dispara a mensagem de redefinição.
    Nota: Por segurança, evitamos expor se o e-mail existe ou não na base.
    """
    # Em arquitetura multi-tenant com base compartilhada, busca o usuário pelo e-mail
    user = db.query(User).filter(User.email == payload.email, User.is_active == True).first()

    if user:
        # Gera token criptograficamente seguro
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)

        # Salva o token e a expiração no registro do usuário (isolado pelo tenant do usuário)
        user.reset_token = token
        user.reset_token_expires_at = expires_at
        db.commit()

        # Dispara o envio do e-mail
        send_reset_email(user.email, token)

    # Retorna sucesso genérico para prevenir enumeração de usuários
    return {
        "message": "Se o e-mail informado estiver cadastrado, você receberá as instruções de recuperação em breve."
    }


@router.post("/reset-password", status_code=status.HTTP_200_OK)
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    """
    Recebe o token de recuperação e a nova senha, valida a integridade
    e conclui a alteração da senha do usuário.
    """
    # Busca o usuário pelo token válido e não expirado
    user = db.query(User).filter(
        User.reset_token == payload.token,
        User.reset_token_expires_at > datetime.utcnow()
    ).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token inválido ou expirado."
        )

    # Atualiza a senha com o hash seguro e invalida o token utilizado
    user.password_hash = pwd_context.hash(payload.new_password)
    user.reset_token = None
    user.reset_token_expires_at = None
    
    db.commit()

    return {
        "message": "Senha alterada com sucesso."
    }