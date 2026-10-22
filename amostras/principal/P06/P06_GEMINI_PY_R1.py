import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Integer
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class TicketAttachment(Base):
    __tablename__ = "ticket_attachments"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), nullable=False, index=True)
    ticket_id = Column(String(36), ForeignKey("tickets.id"), nullable=False, index=True)
    file_name = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, nullable=False)
    content_type = Column(String(100), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

import os
import uuid
import shutil
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status
from sqlalchemy.orm import Session

# Configuração de limites e armazenamento
UPLOAD_BASE_DIR = Path("/var/uploads/saas_data")
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # Limite de 10 MB
ALLOWED_CONTENT_TYPES = {
    "image/jpeg", "image/png", "application/pdf",
    "text/plain", "application/zip"
}

router = APIRouter(prefix="/api/v1/tickets", tags=["Support Tickets"])

# --- Mocks para dependências do sistema ---
def get_db():
    """Injeta a sessão do banco de dados (mock)."""
    db = None  # Substituir por SessionLocal() na aplicação real
    try:
        yield db
    finally:
        pass

class UserContext:
    def __init__(self, user_id: str, tenant_id: str):
        self.user_id = user_id
        self.tenant_id = tenant_id

def get_current_user() -> UserContext:
    """Extrai o usuário e tenant do token JWT validado (mock)."""
    return UserContext(user_id="usr_12345", tenant_id="tenant_9988")
# ------------------------------------------


@router.post("/{ticket_id}/attachments", status_code=status.HTTP_201_CREATED)
async def upload_ticket_attachment(
    ticket_id: str,
    file: UploadFile = File(...),
    current_user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db)):
    """
    Recebe um arquivo enviado como anexo de um chamado de suporte,
    valida permissões/tenant, grava no servidor e registra no banco de dados.
    """
    # 1. Validação do tipo MIME do arquivo
    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tipo de arquivo não permitido."
        )

    # 2. Verificação do Chamado e Pertencimento ao Tenant (Isolamento Multi-tenant)
    # Exemplo sintático de validação no banco:
    # ticket = db.query(Ticket).filter(
    #     Ticket.id == ticket_id,
    #     Ticket.tenant_id == current_user.tenant_id
    # ).first()
    # if not ticket:
    #     raise HTTPException(status_code=404, detail="Chamado não encontrado.")

    # 3. Definição do diretório seguro mantendo isolamento por Tenant
    tenant_directory = UPLOAD_BASE_DIR / current_user.tenant_id / "tickets" / ticket_id
    tenant_directory.mkdir(parents=True, exist_ok=True)

    # 4. Sanitização e criação de um nome de arquivo único
    file_extension = Path(file.filename).suffix.lower()
    unique_filename = f"{uuid.uuid4().hex}{file_extension}"
    destination_path = tenant_directory / unique_filename

    # 5. Escrita no disco com verificação de tamanho máximo
    bytes_written = 0
    try:
        with destination_path.open("wb") as buffer:
            while chunk := await file.read(1024 * 1024):  # Leitura em pedaços de 1 MB
                bytes_written += len(chunk)
                if bytes_written > MAX_FILE_SIZE_BYTES:
                    buffer.close()
                    destination_path.unlink(missing_ok=True)  # Remove arquivo parcial
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="O arquivo excede o tamanho máximo permitido de 10 MB."
                    )
                buffer.write(chunk)
    except Exception as exc:
        if destination_path.exists():
            destination_path.unlink()
        if isinstance(exc, HTTPException):
            raise exc
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao gravar o arquivo no servidor."
        )

    # 6. Registro da relação no Banco de Dados
    attachment_record = TicketAttachment(
        tenant_id=current_user.tenant_id,
        ticket_id=ticket_id,
        file_name=file.filename,  # Nome original enviado pelo cliente
        file_path=str(destination_path),
        file_size=bytes_written,
        content_type=file.content_type
    )

    # db.add(attachment_record)
    # db.commit()
    # db.refresh(attachment_record)

    return {
        "id": attachment_record.id,
        "ticket_id": attachment_record.ticket_id,
        "file_name": attachment_record.file_name,
        "file_size_bytes": attachment_record.file_size,
        "status": "sucesso"
    }