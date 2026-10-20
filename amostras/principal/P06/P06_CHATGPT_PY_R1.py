
import os
import uuid
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_current_user
from app.models import Ticket, TicketAttachment, User
from app.subscriptions import require_active_subscription


router = APIRouter(prefix="/tickets", tags=["Attachments"])

UPLOAD_DIR = Path("/var/lib/minha-saas/attachments")
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

ALLOWED_EXTENSIONS = {
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".txt",
}

ALLOWED_CONTENT_TYPES = {
    ".pdf": {"application/pdf"},
    ".png": {"image/png"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".txt": {"text/plain"},
}


@router.post(
    "/{ticket_id}/attachments",
    status_code=status.HTTP_201_CREATED,
)
def upload_ticket_attachment(
    ticket_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    subscription=Depends(require_active_subscription),
):
    # 1. Validar o acesso ao chamado no contexto do tenant.
    ticket = (
        db.query(Ticket)
        .filter(
            Ticket.id == ticket_id,
            Ticket.tenant_id == current_user.tenant_id,
        )
        .first()
    )

    if ticket is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chamado não encontrado.",
        )

    # 2. Validar o nome e o tipo declarado do arquivo.
    original_name = Path(file.filename or "").name
    extension = Path(original_name).suffix.lower()

    if (
        not original_name
        or extension not in ALLOWED_EXTENSIONS
        or file.content_type
        not in ALLOWED_CONTENT_TYPES[extension]
    ):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Tipo de arquivo não permitido.",
        )

    # 3. Gerar um nome físico imprevisível.
    attachment_id = uuid.uuid4()
    stored_name = f"{attachment_id}{extension}"

    # Separar os arquivos por empresa.
    tenant_dir = UPLOAD_DIR / str(current_user.tenant_id)
    tenant_dir.mkdir(parents=True, exist_ok=True)

    file_path = tenant_dir / stored_name
    total_size = 0

    try:
        # 4. Gravar em blocos e limitar o tamanho real recebido.
        with file_path.open("xb") as destination:
            while True:
                chunk = file.file.read(64 * 1024)

                if not chunk:
                    break

                total_size += len(chunk)

                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail="O arquivo excede o limite de 10 MB.",
                    )

                destination.write(chunk)

        # 5. Persistir os metadados e o vínculo com o chamado.
        attachment = TicketAttachment(
            id=attachment_id,
            ticket_id=ticket.id,
            tenant_id=current_user.tenant_id,
            uploaded_by=current_user.id,
            original_name=original_name,
            stored_name=stored_name,
            storage_path=str(file_path),
            content_type=file.content_type,
            size_bytes=total_size,
        )

        db.add(attachment)
        db.commit()
        db.refresh(attachment)

        return {
            "id": str(attachment.id),
            "ticket_id": ticket.id,
            "original_name": attachment.original_name,
            "content_type": attachment.content_type,
            "size_bytes": attachment.size_bytes,
            "message": "Anexo enviado com sucesso.",
        }

    except HTTPException:
        db.rollback()
        file_path.unlink(missing_ok=True)
        raise

    except Exception:
        db.rollback()
        file_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível salvar o anexo.",
        )

    finally:
        file.file.close()
