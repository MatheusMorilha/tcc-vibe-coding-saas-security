import os
import datetime
from typing import Optional
from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
import jwt
from passlib.context import CryptContext

# -----------------------------------------------------------------------------
# Configurações de Segurança e Constantes
# -----------------------------------------------------------------------------
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "SUA_CHAVE_SECRETA_SUPER_SEGURA")
ALGORITHM = "HS256"
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = 15

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# -----------------------------------------------------------------------------
# Schemas (Pydantic)
# -----------------------------------------------------------------------------
class RequestPasswordResetSchema(BaseModel):
    email: EmailStr

class ResetPasswordSchema(BaseModel):
    token: str
    new_password: str

class MessageResponseSchema(BaseModel):
    message: str

# -----------------------------------------------------------------------------
# Funções Utilitárias de Segurança e Token
# -----------------------------------------------------------------------------
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_password_reset_token(email: str, tenant_id: str, password_hash: str) -> str:
    """
    Gera token JWT contendo email, tenant_id e um fragmento do hash da senha
    atual para garantir que o token seja inutilizado assim que a senha for alterada.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    expire = now + datetime.timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": email,
        "tenant_id": tenant_id,
        "pwd_sig": password_hash[-10:],  # Assinatura baseada no hash atual
        "exp": expire,
        "iat": now,
        "type": "password_reset"
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_password_reset_token(token: str) -> dict:
    """Valida o token JWT e retorna o payload extraído."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "password_reset":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Tipo de token inválido."
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O link de redefinição de senha expirou."
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token de redefinição de senha inválido."
        )

def send_reset_email_task(email: EmailStr, token: str):
    """Função assíncrona/background para envio do e-mail de redefinição."""
    reset_link = f"https://app.suaplataforma.com/reset-password?token={token}"
    # Lógica de envio (ex: via SendGrid, Amazon SES, Mailgun)
    # send_email(to=email, subject="Redefinição de Senha", body=f"Acesse: {reset_link}")
    print(f"[MOCK EMAIL] Enviado para {email}: {reset_link}")

# -----------------------------------------------------------------------------
# Rotas da API (FastAPI Router)
# -----------------------------------------------------------------------------
router = APIRouter(prefix="/auth", tags=["Autenticação"])

# Exemplo de Injeção de Dependência da Sessão do Banco de Dados
def get_db():
    # Retorna sessão do SQLAlchemy
    pass

@router.post(
    "/forgot-password",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK)
def request_password_reset(
    data: RequestPasswordResetSchema,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)):
    """
    1. Rota que recebe o e-mail do usuário e dispara o e-mail com o token de redefinição.
    """
    # Consulta o usuário na base (busca global por e-mail no cenário multilocatário)
    # user = db.query(UserModel).filter(UserModel.email == data.email).first()
    user = None  # Substituir pela consulta real no DB

    if user and user.is_active:
        token = create_password_reset_token(
            email=user.email,
            tenant_id=user.tenant_id,
            password_hash=user.password_hash
        )
        # Dispara o e-mail em background para não bloquear a resposta HTTP
        background_tasks.add_task(send_reset_email_task, user.email, token)

    # Retorna sempre a mesma resposta genérica para evitar enumeração de usuários
    return MessageResponseSchema(
        message="Se o e-mail estiver cadastrado em nosso sistema, você receberá as instruções para redefinição em instantes."
    )


@router.post(
    "/reset-password",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK)
def reset_password(
    data: ResetPasswordSchema,
    db: Session = Depends(get_db)):
    """
    2. Rota que recebe o token e a nova senha, concluindo a alteração.
    """
    # Valida e decodifica o token JWT
    payload = verify_password_reset_token(data.token)
    email: str = payload.get("sub")
    tenant_id: str = payload.get("tenant_id")
    pwd_sig: str = payload.get("pwd_sig")

    # Busca o usuário validando estritamente o tenant_id e o e-mail
    # user = db.query(UserModel).filter(
    #     UserModel.email == email,
    #     UserModel.tenant_id == tenant_id
    # ).first()
    user = None  # Substituir pela consulta real no DB

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado ou inativo."
        )

    # Verifica se o token já foi utilizado através do fragmento do hash antigo
    if user.password_hash[-10:] != pwd_sig:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este token de redefinição já foi utilizado ou é inválido."
        )

    # Atualiza a senha e persiste no banco
    user.password_hash = get_password_hash(data.new_password)
    # db.add(user)
    # db.commit()

    return MessageResponseSchema(
        message="Senha redefinida com sucesso. Você já pode realizar o login com a nova senha."
    )