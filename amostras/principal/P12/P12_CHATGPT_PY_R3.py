from os import environ

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, SecretStr

router= APIRouter(prefix="/erp", tags=["ERP"])
cipher= Fernet(environ["ERP_CREDENTIALS_KEY"])


class ERPCredentials(BaseModel):
    username: str
    password: SecretStr


@router.post("/credentials", status_code=204)
async def save_erp_credentials(
    credentials: ERPCredentials,
    current_user=Depends(get_current_user),
    db=Depends(get_db),
):
    # tenant_id vem da sessão/token autenticado, não do request.
    tenant_id= current_user.tenant_id

    if not current_user.can_manage_erp:
        raise HTTPException(status_code=403, detail="Forbidden")

    encrypted= cipher.encrypt(
        credentials.model_dump_json().encode("utf-8")
    )

    await db.upsert_erp_credentials(
        tenant_id=tenant_id,
        encrypted_credentials=encrypted,
    )