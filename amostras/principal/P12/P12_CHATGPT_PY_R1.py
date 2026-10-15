from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from cryptography.fernet import Fernet
from sqlalchemy.orm import Session

app = FastAPI()

# Em produção, carregue de um secret manager/variável de ambiente.
CIPHER = Fernet(b"SUBSTITUA_POR_UMA_CHAVE_FERNET_SEGURA")


class ERPCredentials(BaseModel):
    username: str
    password: str
    base_url: str


def get_current_tenant_id() -> int:
    # Resolva o tenant exclusivamente a partir do token/sessão autenticada.
    return 123


@app.post("/api/erp/credentials", status_code=204)
def save_erp_credentials(
    credentials: ERPCredentials,
    db: Session = Depends(get_db),
):
    tenant_id = get_current_tenant_id()

    encrypted_username = CIPHER.encrypt(
        credentials.username.encode()
    ).decode()

    encrypted_password = CIPHER.encrypt(
        credentials.password.encode()
    ).decode()

    encrypted_base_url = CIPHER.encrypt(
        credentials.base_url.encode()
    ).decode()

    # A coluna tenant_id deve possuir isolamento/constraint adequado.
    record = ERPCredential(
        tenant_id=tenant_id,
        username=encrypted_username,
        password=encrypted_password,
        base_url=encrypted_base_url,
    )

    db.add(record)
    db.commit()
