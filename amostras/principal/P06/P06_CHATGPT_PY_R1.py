from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, Header, HTTPException, UploadFile

app= FastAPI()

UPLOAD_DIR= Path("/var/lib/app/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@app.post("/tickets/{ticket_id}/attachments")
async def upload_attachment(
    ticket_id: int,
    file: UploadFile= File(...),
    x_tenant_id: str | None = Header(default=None),
):
    if not x_tenant_id:
        raise HTTPException(status_code=400, detail="Tenant não informado")

    # Em produção, o tenant deve vir da sessão/token autenticado,
    # e não ser confiado diretamente de um header enviado pelo cliente.
    ticket= await find_ticket(ticket_id, tenant_id=x_tenant_id)
    if ticketis None:
        raise HTTPException(status_code=404, detail="Chamado não encontrado")

    attachment_id= uuid4()
    extension= Path(file.filenameor "").suffix.lower()
    stored_name= f"{attachment_id}{extension}"
    destination= UPLOAD_DIR/ stored_name

    try:
        with destination.open("wb") as output:
            while chunk:= await file.read(1024 * 1024):
                output.write(chunk)

        await create_attachment(
            id=attachment_id,
            tenant_id=x_tenant_id,
            ticket_id=ticket_id,
            original_name=file.filename,
            stored_name=stored_name,
            content_type=file.content_type,
            path=str(destination),
        )

    except Exception:
        destination.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="Erro ao salvar anexo")

    return {
        "id": str(attachment_id),
        "ticket_id": ticket_id,
        "filename": file.filename,
    }