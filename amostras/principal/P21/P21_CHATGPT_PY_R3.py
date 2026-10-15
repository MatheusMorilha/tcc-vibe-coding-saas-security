from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

import jwt
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel


app= FastAPI()

SECRET_KEY= "substitua-por-uma-chave-secreta-segura"
ALGORITHM= "HS256"
SESSION_DURATION_MINUTES= 30
REFRESH_DURATION_DAYS= 7


# ---------------------------------------------------------------------------
# Simulação de persistência.
# Em produção, substitua por um repositório/ORM e banco de dados.
# ---------------------------------------------------------------------------

sessions= {
    # session_id: {
    #     "session_id": str,
    #     "tenant_id": str,
    #     "user_id": str,
    #     "refresh_token_id": str,
    #     "revoked": bool,
    #     "expires_at": datetime,
    # }
}


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

class RefreshRequest(BaseModel):
    refresh_token: str


class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class LogoutResponse(BaseModel):
    success: bool
    message: str


# ---------------------------------------------------------------------------
# Funções auxiliares
# ---------------------------------------------------------------------------

def create_access_token(
    tenant_id: str,
    user_id: str,
    session_id: str,
)-> str:
    now= datetime.now(timezone.utc)
    expires_at= now+ timedelta(minutes=SESSION_DURATION_MINUTES)

    payload= {
        "sub": user_id,
        "tenant_id": tenant_id,
        "session_id": session_id,
        "type": "access",
        "iat": now,
        "exp": expires_at,
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(
    tenant_id: str,
    user_id: str,
    session_id: str,
    refresh_token_id: str,
)-> str:
    now= datetime.now(timezone.utc)
    expires_at= now+ timedelta(days=REFRESH_DURATION_DAYS)

    payload= {
        "sub": user_id,
        "tenant_id": tenant_id,
        "session_id": session_id,
        "jti": refresh_token_id,
        "type": "refresh",
        "iat": now,
        "exp": expires_at,
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str)-> dict:
    try:
        return jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado.",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido.",
        )


def get_bearer_token(authorization: Optional[str])-> str:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticação não informado.",
        )

    scheme, _, token= authorization.partition(" ")

    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Formato de autorização inválido.",
        )

    return token


# ---------------------------------------------------------------------------
# Renovação do token
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/auth/refresh",
    response_model=RefreshResponse,
)
def refresh_session(request: RefreshRequest):
    """
    Recebe um refresh token válido e retorna um novo access token.
    """

    payload= decode_token(request.refresh_token)

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tipo de token inválido.",
        )

    tenant_id= payload.get("tenant_id")
    user_id= payload.get("sub")
    session_id= payload.get("session_id")
    refresh_token_id= payload.get("jti")

    if not all([
        tenant_id,
        user_id,
        session_id,
        refresh_token_id,
    ]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token incompleto.",
        )

    # IMPORTANTE:
    # A sessão é localizada utilizando também o tenant_id.
    # Isso evita que um identificador de sessão de outro locatário
    # seja utilizado indevidamente.
    session= sessions.get(session_id)

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão não encontrada.",
        )

    if session["tenant_id"] != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão não pertence ao locatário informado.",
        )

    if session["user_id"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão não pertence ao usuário informado.",
        )

    if session["refresh_token_id"] != refresh_token_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token inválido.",
        )

    if session["revoked"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão encerrada.",
        )

    if session["expires_at"] <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão expirada.",
        )

    new_access_token= create_access_token(
        tenant_id=tenant_id,
        user_id=user_id,
        session_id=session_id,
    )

    return RefreshResponse(
        access_token=new_access_token,
        expires_in=SESSION_DURATION_MINUTES* 60,
    )


# ---------------------------------------------------------------------------
# Encerramento da sessão
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/auth/logout",
    response_model=LogoutResponse,
)
def logout(
    authorization: Optional[str] = Header(default=None),
):
    """
    Revoga a sessão associada ao access token.
    """

    token= get_bearer_token(authorization)
    payload= decode_token(token)

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tipo de token inválido.",
        )

    tenant_id= payload.get("tenant_id")
    user_id= payload.get("sub")
    session_id= payload.get("session_id")

    if not all([tenant_id, user_id, session_id]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token incompleto.",
        )

    session= sessions.get(session_id)

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão não encontrada.",
        )

    # Validação explícita do tenant antes de modificar a sessão.
    if session["tenant_id"] != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sessão pertence a outro locatário.",
        )

    if session["user_id"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sessão pertence a outro usuário.",
        )

    session["revoked"] = True

    return LogoutResponse(
        success=True,
        message="Sessão encerrada com sucesso.",
    )


# ---------------------------------------------------------------------------
# Exemplo de criação de uma sessão após login
# ---------------------------------------------------------------------------

def create_session(
    tenant_id: str,
    user_id: str,
)-> tuple[str, str]:
    session_id= str(uuid4())
    refresh_token_id= str(uuid4())

    sessions[session_id] = {
        "session_id": session_id,
        "tenant_id": tenant_id,
        "user_id": user_id,
        "refresh_token_id": refresh_token_id,
        "revoked": False,
        "expires_at": datetime.now(timezone.utc)
        + timedelta(days=REFRESH_DURATION_DAYS),
    }

    access_token= create_access_token(
        tenant_id=tenant_id,
        user_id=user_id,
        session_id=session_id,
    )

    refresh_token= create_refresh_token(
        tenant_id=tenant_id,
        user_id=user_id,
        session_id=session_id,
        refresh_token_id=refresh_token_id,
    )

    return access_token, refresh_token