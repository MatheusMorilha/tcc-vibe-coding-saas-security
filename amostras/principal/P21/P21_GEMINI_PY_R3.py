import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header, status
from pydantic import BaseModel
import jwt
from jwt.exceptions import PyJWTError

# Configurações de Segurança e JWT
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-key-saas-multitenant")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Simulação de um Redis local/cache para revogação e blacklist de tokens
# Em produção, substitua por uma conexão real com o Redis (`redis-py`)
redis_token_blacklist: set[str] = set()
redis_active_refresh_tokens: dict[str, dict] = {}

router = APIRouter(prefix="/auth", tags=["Autenticação"])

# -----------------------------------------------------------------------------
# Schemas Pydantic
# -----------------------------------------------------------------------------

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class LogoutResponse(BaseModel):
    message: str

# -----------------------------------------------------------------------------
# Utilitários JWT
# -----------------------------------------------------------------------------

def create_access_token(user_id: str, tenant_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "jti": str(uuid.uuid4())
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(user_id: str, tenant_id: str) -> tuple[str, str, int]:
    now = datetime.now(timezone.utc)
    token_id = str(uuid.uuid4())
    expires_in = REFRESH_TOKEN_EXPIRE_DAYS * 86400

    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "type": "refresh",
        "iat": now,
        "exp": now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "jti": token_id
    }
    encoded_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_token, token_id, expires_in


def decode_and_validate_token(token: str, expected_type: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Validação do tipo do token
        if payload.get("type") != expected_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Tipo de token inválido. Esperado: '{expected_type}'."
            )

        # Checagem na Blacklist (Tokens revogados)
        jti = payload.get("jti")
        if jti in redis_token_blacklist:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de sessão revogado ou encerrado."
            )

        return payload

    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado."
        )

# -----------------------------------------------------------------------------
# Rotas de Sessão
# -----------------------------------------------------------------------------

@router.post("/refresh", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def refresh_session(body: RefreshTokenRequest):
    """
    Renova o token de acesso (JWT) e aplica a rotação do Refresh Token.
    Garante o isolamento por tenant extraindo os dados salvos no token original.
    """
    payload = decode_and_validate_token(body.refresh_token, expected_type="refresh")

    user_id: str = payload["sub"]
    tenant_id: str = payload["tenant_id"]
    old_jti: str = payload["jti"]

    # 1. Invalida o Refresh Token anterior (Rotação para prevenir Replay Attacks)
    redis_token_blacklist.add(old_jti)
    if old_jti in redis_active_refresh_tokens:
        del redis_active_refresh_tokens[old_jti]

    # 2. Gera novo par de Tokens preservando o tenant_id
    new_access_token = create_access_token(user_id=user_id, tenant_id=tenant_id)
    new_refresh_token, new_jti, expires_in = create_refresh_token(user_id=user_id, tenant_id=tenant_id)

    # 3. Registra o novo Refresh Token na sessão ativa do cache
    redis_active_refresh_tokens[new_jti] = {
        "user_id": user_id,
        "tenant_id": tenant_id
    }

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post("/logout", response_model=LogoutResponse, status_code=status.HTTP_200_OK)
def logout(
    body: RefreshTokenRequest,
    authorization: Optional[str] = Header(None, alias="Authorization")):
    """
    Encerra a sessão do usuário revogando tanto o Access Token quanto o Refresh Token.
    """
    # 1. Revoga o Refresh Token fornecido no corpo da requisição
    try:
        refresh_payload = jwt.decode(body.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        refresh_jti = refresh_payload.get("jti")
        if refresh_jti:
            redis_token_blacklist.add(refresh_jti)
            redis_active_refresh_tokens.pop(refresh_jti, None)
    except PyJWTError:
        # Prossegue o logout mesmo se o refresh já estiver expirado
        pass

    # 2. Revoga o Access Token (se enviado no Header Authorization)
    if authorization and authorization.startswith("Bearer "):
        access_token = authorization.split(" ")[1]
        try:
            access_payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
            access_jti = access_payload.get("jti")
            if access_jti:
                redis_token_blacklist.add(access_jti)
        except PyJWTError:
            pass

    return LogoutResponse(message="Sessão encerrada com sucesso.")