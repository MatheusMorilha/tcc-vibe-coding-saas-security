import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from pydantic import BaseModel

# -----------------------------------------------------------------------------
# Configurações de Segurança e JWT
# -----------------------------------------------------------------------------
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "SUA_CHAVE_SECRETA_SUPER_SEGURA")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Esquema OAuth2 para extração do Bearer Token do cabeçalho Authorization
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

router = APIRouter(prefix="/api/v1/auth", tags=["Autenticação & Sessão"])


# -----------------------------------------------------------------------------
# Modelos Pydantic (DTOs)
# -----------------------------------------------------------------------------
class RefreshTokenRequest(BaseModel):
    refresh_token: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # Tempo em segundos até expirar

class MessageResponse(BaseModel):
    message: str


# -----------------------------------------------------------------------------
# Auxiliares para Manipulação de Tokens
# -----------------------------------------------------------------------------
def create_access_token(user_id: str, tenant_id: str) -> str:
    """Gera um JWT Access Token com o contexto do Tenant e Usuário."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_and_validate_token(token: str, expected_type: str) -> dict:
    """Valida assinatura, expiração e tipo do token JWT."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != expected_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Tipo de token inválido. Esperado: '{expected_type}'."
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado."
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou adulterado."
        )


# Simulated Token Blacklist (Em produção, utilize Redis/KeyDB com TTL)
REVOKED_TOKENS_STORE: set[str] = set()

def is_token_revoked(token: str) -> bool:
    return token in REVOKED_TOKENS_STORE

def revoke_token(token: str) -> None:
    REVOKED_TOKENS_STORE.add(token)


# -----------------------------------------------------------------------------
# Rotas da API
# -----------------------------------------------------------------------------

@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Renova o token de acesso (Session Refresh)")
async def refresh_session(payload: RefreshTokenRequest):
    """
    Recebe um Refresh Token válido e gera um novo Access Token mantendo
    o isolamento de tenant_id e user_id do usuário logado.
    """
    # 1. Verificar se o refresh token foi revogado/invalidado
    if is_token_revoked(payload.refresh_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="O Refresh Token fornecido foi revogado."
        )

    # 2. Validar o refresh token e extrair as claims do usuário e tenant
    token_data = decode_and_validate_token(payload.refresh_token, expected_type="refresh")

    user_id: str = token_data.get("sub")
    tenant_id: str = token_data.get("tenant_id")

    if not user_id or not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Payload do token incompleto para contexto SaaS."
        )

    # 3. Gerar novo Access Token com o mesmo contexto de locatário
    new_access_token = create_access_token(user_id=user_id, tenant_id=tenant_id)

    return TokenResponse(
        access_token=new_access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Encerra a sessão do usuário (Logout)")
async def logout(
    refresh_payload: Optional[RefreshTokenRequest] = None,
    current_token: str = Depends(oauth2_scheme)):
    """
    Encerra a sessão ativa invalidando o Access Token atual e, opcionalmente,
    o Refresh Token fornecido no corpo da requisição.
    """
    # 1. Validar e revogar o Access Token recebido no header Authorization
    decode_and_validate_token(current_token, expected_type="access")
    revoke_token(current_token)

    # 2. Se um Refresh Token também for enviado, revogá-lo
    if refresh_payload and refresh_payload.refresh_token:
        try:
            decode_and_validate_token(refresh_payload.refresh_token, expected_type="refresh")
            revoke_token(refresh_payload.refresh_token)
        except HTTPException:
            # Ignora se o refresh token já estiver expirado no ato do logout
            pass

    return MessageResponse(message="Sessão encerrada com sucesso.")