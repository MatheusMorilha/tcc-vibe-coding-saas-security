from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

app = FastAPI()

SECRET_KEY = "substitua-por-uma-chave-secreta-forte"
ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 30
REFRESH_TOKEN_DAYS = 7

security = HTTPBearer()


def create_token(user_id: str, tenant_id: str, token_type: str, expires_delta: timedelta):
    now = datetime.now(timezone.utc)

    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "type": token_type,
        "iat": now,
        "exp": now + expires_delta,
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado",
        )


def current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
):
    payload = decode_token(credentials.credentials)

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de acesso esperado",
        )

    return payload


@app.post("/auth/refresh")
def refresh_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
):
    payload = decode_token(credentials.credentials)

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token esperado",
        )

    user_id = payload.get("sub")
    tenant_id = payload.get("tenant_id")

    if not user_id or not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
        )

    # Em produção, validar aqui:
    # - existência do usuário no tenant_id
    # - status ativo do usuário
    # - status da assinatura do tenant
    # - revogação/rotação do refresh token

    new_access_token = create_token(
        user_id=user_id,
        tenant_id=tenant_id,
        token_type="access",
        expires_delta=timedelta(minutes=ACCESS_TOKEN_MINUTES),
    )

    return {
        "access_token": new_access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_MINUTES * 60,
    }


@app.post("/auth/logout")
def logout(
    user: Annotated[dict, Depends(current_user)],
):
    user_id = user["sub"]
    tenant_id = user["tenant_id"]

    # Em produção, registrar o JTI do token em uma blacklist/revocation store
    # ou invalidar a sessão correspondente no banco/Redis.
    #
    # A consulta deve sempre considerar tenant_id para impedir
    # acesso cruzado entre empresas.

    return {
        "success": True,
        "message": "Sessão encerrada com sucesso",
        "user_id": user_id,
        "tenant_id": tenant_id,
    }
