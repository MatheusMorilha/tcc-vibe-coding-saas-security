from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from pathlib import Path
from uuid import uuid4
import shutil

app= FastAPI()

UPLOAD_DIR= Path("/var/lib/saas/attachments")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


class CurrentUser:
    def __init__(self, user_id: int, tenant_id: int):
        self.id= user_id
        self.tenant_id= tenant_id


def get_current_user()-> CurrentUser:
    # Substituir pela autenticação real.
    return CurrentUser(user_id=1, tenant_id=42)


def get_ticket(ticket_id: int, tenant_id: int):
    # A consulta DEVE filtrar pelo tenant.
    return {"id": ticket_id, "tenant_id": tenant_id}


def save_attachment_record(
    tenant_id: int,
    ticket_id: int,
    user_id: int,
    filename: str,
    storage_path: str,
):
    # Persistir em banco: tenant_id, ticket_id, user_id,
    # nome original, caminho físico, tamanho, MIME etc.
    pass


@app.post("/tickets/{ticket_id}/attachments")
async def upload_attachment(
    ticket_id: int,
    file: UploadFile= File(...),
    user: CurrentUser= Depends(get_current_user),
):
    ticket= get_ticket(ticket_id, user.tenant_id)

    if not ticket:
        raise HTTPException(status_code=404, detail="Chamado não encontrado")

    attachment_id= uuid4()
    extension= Path(file.filenameor "").suffix
    filename= f"{attachment_id}{extension}"

    tenant_dir= UPLOAD_DIR/ str(user.tenant_id)
    tenant_dir.mkdir(parents=True, exist_ok=True)

    destination= tenant_dir/ filename

    try:
        with destination.open("wb") as output:
            shutil.copyfileobj(file.file, output)

        save_attachment_record(
            tenant_id=user.tenant_id,
            ticket_id=ticket_id,
            user_id=user.id,
            filename=file.filenameor filename,
            storage_path=str(destination),
        )

        return {
            "id": str(attachment_id),
            "ticket_id": ticket_id,
            "filename": file.filename,
        }

    except Exception:
        if destination.exists():
            destination.unlink()
        raise HTTPException(
            status_code=500,
            detail="Não foi possível salvar o anexo",
        )