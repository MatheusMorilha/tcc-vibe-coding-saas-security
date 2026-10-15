import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import jwt

# ==========================================
# Configurações de Ambiente e Segurança
# ==========================================
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "sua_chave_secreta_super_segura")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Mock de Redis / Cache para armazenamento de tokens revogados (Blacklist)
REVOKED_TOKENS: set[str] = set()

security = HTTPBearer()
app = FastAPI(title="SaaS Multi-tenant Auth API")

# ==========================================
# Schemas (Pydantic Models)
# ==========================================
class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token JWT enviado pelo cliente.")

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in_seconds: int

class LogoutResponse(BaseModel):
    message: str
    success: bool

# ==========================================
# Funções Utilitárias de JWT
# ==========================================
def create_token(data: dict, expires_delta: timedelta) -> str:
    """Gera um JWT incluindo payload de expiração e dados de contexto multi-tenant."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_and_validate_token(token: str, token_type: str = "refresh") -> dict:
    """Decodifica e valida assinatura, expiração, tipo e revogação do token."""
    if token in REVOKED_TOKENS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token revogado ou sessão encerrada."
        )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        if payload.get("type") != token_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Tipo de token inválido. Esperado '{token_type}'."
            )

        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado."
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido."
        )

# ==========================================
# Rotas da API
# ==========================================

@app.post(
    "/api/v1/auth/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Renova o token de acesso do usuário")
def refresh_session_token(body: RefreshTokenRequest):
    """
    Recebe um refresh token válido, decodifica o contexto do usuário/tenant e
    emite um novo par de tokens (Access Token + Refresh Token Rotacionado).
    """
    payload = decode_and_validate_token(body.refresh_token, token_type="refresh")

    # Extração das claims essenciais do modelo SaaS multi-tenant
    user_id = payload.get("sub")
    tenant_id = payload.get("tenant_id")
    role = payload.get("role")

    if not user_id or not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Claims do token incompletas (user_id/tenant_id ausentes)."
        )

    # Invalida o refresh token atual para implementar 'Refresh Token Rotation'
    REVOKED_TOKENS.add(body.refresh_token)

    # Criação dos novos tokens preservando a restrição e isolamento do tenant_id
    new_payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "role": role
    }

    new_access_token = create_token(
        data={**new_payload, "type": "access"},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    new_refresh_token = create_token(
        data={**new_payload, "type": "refresh"},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in_seconds=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@app.post(
    "/api/v1/auth/logout",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="Encerra a sessão do usuário")
def logout_user(
    body: RefreshTokenRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Encerra a sessão ativa. Revoga tanto o Access Token enviado no Header
    quanto o Refresh Token informado no corpo da requisição.
    """
    access_token = credentials.credentials

    # Adiciona ambos os tokens à blacklist de revogação
    REVOKED_TOKENS.add(access_token)
    REVOKED_TOKENS.add(body.refresh_token)

    return LogoutResponse(
        message="Sessão encerrada com sucesso.",
        success=True
    )