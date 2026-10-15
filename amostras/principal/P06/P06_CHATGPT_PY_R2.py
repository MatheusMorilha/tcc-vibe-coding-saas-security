from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, UploadFile, HTTPException, Depends

app= FastAPI()

UPLOAD_DIR= Path("/srv/app/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def get_current_user():
    # Substituir pelo mecanismo real de autenticação.
    return {"id": 123, "tenant_id": 42}


def get_ticket(ticket_id: int, tenant_id: int):
    # Consultar o chamado garantindo isolamento pelo tenant_id.
    return {"id": ticket_id, "tenant_id": tenant_id}


def save_attachment_record(tenant_id: int, ticket_id: int,
                           filename: str, storage_name: str):
    # Persistir o vínculo em uma tabela de anexos.
    pass


@app.post("/tickets/{ticket_id}/attachments")
async def upload_attachment(
    ticket_id: int,
    file: UploadFile= File(...),
    user=Depends(get_current_user),
):
    ticket= get_ticket(ticket_id, user["tenant_id"])

    if not ticket:
        raise HTTPException(status_code=404, detail="Chamado não encontrado")

    if not file.filename:
        raise HTTPException(status_code=400, detail="Arquivo inválido")

    # Nunca usar diretamente o nome enviado pelo cliente no caminho físico.
    extension= Path(file.filename).suffix
    storage_name= f"{uuid4().hex}{extension}"
    destination= UPLOAD_DIR/ storage_name

    try:
        with destination.open("wb") as output:
            while chunk:= await file.read(1024 * 1024):
                output.write(chunk)

        save_attachment_record(
            tenant_id=user["tenant_id"],
            ticket_id=ticket["id"],
            filename=file.filename,
            storage_name=storage_name,
        )

        return {
            "message": "Anexo enviado com sucesso",
            "filename": file.filename,
        }

    except Exception:
        destination.unlink(missing_ok=True)
        raise HTTPException(
            status_code=500,
            detail="Não foi possível salvar o anexo",
        )