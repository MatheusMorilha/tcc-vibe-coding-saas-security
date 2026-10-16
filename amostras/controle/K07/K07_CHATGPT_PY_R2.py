from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from pwdlib import PasswordHash

from app.db import get_db
from app.models import User, SessionToken


router = APIRouter(prefix="/auth", tags=["authentication"])

# Argon2id é usado pelo PasswordHash recomendado pelo pwdlib.
password_hash = PasswordHash.recommended()

SESSION_TTL = timedelta(hours=8)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int


def normalize_email(email: str) -> str:
    return email.strip().casefold()


def hash_session_token(token: str) -> str:
    """
    O token bruto nunca é persistido.
    SHA-256 é adequado aqui porque o token é aleatório
    criptograficamente forte e não é uma senha escolhida pelo usuário.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def authenticate_user(
    db: Session,
    email: str,
    password: str,
) -> User | None:
    normalized_email = normalize_email(email)

    user = db.scalar(
        select(User).where(
            User.email == normalized_email,
            User.is_active.is_(True),
        )
    )

    # Não revelar se o e-mail existe.
    if user is None:
        # Mantém um custo semelhante ao caso em que o usuário existe.
        password_hash.verify(
            password,
            "$argon2id$v=19$m=65536,t=3,p=4$"
            "AAAAAAAAAAAAAAAAAAAAAA$"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        return None

    if not password_hash.verify(password, user.password_hash):
        return None

    return user


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> LoginResponse:
    user = authenticate_user(
        db=db,
        email=payload.email,
        password=payload.password,
    )

    # Mesma resposta para usuário inexistente e senha incorreta.
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail ou senha inválidos.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # O tenant vem do usuário autenticado, nunca do request.
    tenant_id = user.tenant_id

    raw_token = secrets.token_urlsafe(48)
    token_hash = hash_session_token(raw_token)

    expires_at = datetime.now(timezone.utc) + SESSION_TTL

    session = SessionToken(
        token_hash=token_hash,
        user_id=user.id,
        tenant_id=tenant_id,
        expires_at=expires_at,
        revoked=False,
    )

    db.add(session)
    db.commit()

    return LoginResponse(
        access_token=raw_token,
        expires_in=int(SESSION_TTL.total_seconds()),
    )
