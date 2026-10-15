import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

# Importações genéricas de modelos e sessão do banco
# Adjust imports according to your project structure
from app.db.session import get_db
from app.models import User, VerificationCode
from app.services.notifier import send_verification_code_notification
from app.core.security import get_current_user  # Middleware de autenticação

router = APIRouter(prefix="/auth", tags=["Autenticação"])

# Configurações de tempo limite (podem vir de variáveis de ambiente)
RESEND_COOLDOWN_SECONDS = 60  # Tempo mínimo entre reenviol
CODE_EXPIRATION_MINUTES = 10  # Validade do código


class ResendCodeRequest(BaseModel):
    channel: str = "email"  # 'email' ou 'sms'


class ResendCodeResponse(BaseModel):
    message: str
    cooldown_seconds: int


def generate_secure_code(length: int = 6) -> str:
    """Gera um código numérico aleatório criptograficamente seguro."""
    return "".join([str(secrets.randbelow(10)) for _ in range(length)])


@router.post(
    "/resend-verification-code",
    response_model=ResendCodeResponse,
    status_code=status.HTTP_200_OK,)
def resend_verification_code(
    payload: ResendCodeRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),):
    """
    Reenvia o código de verificação para o usuário autenticado,
    respeitando o isolamento do tenant e políticas de rate limiting.
    """
    now = datetime.now(timezone.utc)

    # 1. Validação do estado do usuário
    if current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O contato deste usuário já foi verificado.",
        )

    # 2. Rate Limiting: Verifica se um código recente já foi emitido
    last_code = (
        db.query(VerificationCode)
        .filter(
            VerificationCode.tenant_id == current_user.tenant_id,
            VerificationCode.user_id == current_user.id,
            VerificationCode.channel == payload.channel,
        )
        .order_by(VerificationCode.created_at.desc())
        .first()
    )

    if last_code:
        elapsed_seconds = (now - last_code.created_at.replace(tzinfo=timezone.utc)).total_seconds()
        if elapsed_seconds < RESEND_COOLDOWN_SECONDS:
            remaining_time = int(RESEND_COOLDOWN_SECONDS - elapsed_seconds)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Aguarde {remaining_time} segundos antes de solicitar um novo código.",
            )

        # Invalida códigos anteriores ainda não utilizados
        db.query(VerificationCode).filter(
            VerificationCode.tenant_id == current_user.tenant_id,
            VerificationCode.user_id == current_user.id,
            VerificationCode.is_used == False,
        ).update({"is_used": True})

    # 3. Geração do novo código de verificação
    code_str = generate_secure_code(length=6)
    expires_at = now + timedelta(minutes=CODE_EXPIRATION_MINUTES)

    new_verification = VerificationCode(
        tenant_id=current_user.tenant_id,  # Garante o isolamento multitenant
        user_id=current_user.id,
        code=code_str,
        channel=payload.channel,
        created_at=now,
        expires_at=expires_at,
        is_used=False,
    )

    db.add(new_verification)
    db.commit()

    # 4. Disparo assíncrono do e-mail/SMS (para não bloquear a resposta HTTP)
    recipient = (
        current_user.email if payload.channel == "email" else current_user.phone_number
    )

    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Usuário não possui {payload.channel} cadastrado.",
        )

    background_tasks.add_task(
        send_verification_code_notification,
        recipient=recipient,
        code=code_str,
        channel=payload.channel,
        tenant_id=str(current_user.tenant_id),
    )

    return ResendCodeResponse(
        message="Código de verificação reenviado com sucesso.",
        cooldown_seconds=RESEND_COOLDOWN_SECONDS,
    )