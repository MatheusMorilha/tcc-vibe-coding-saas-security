import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Integer
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Attachment(Base):
    __tablename__ = "attachments"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), nullable=False, index=True)
    ticket_id = Column(String(36), ForeignKey("tickets.id"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, nullable=False)
    mime_type = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

import os
import uuid
import shutil
from pathlib import Path
from typing import Annotated
from fastapi import FastAPI, APIRouter, UploadFile, File, Form, Depends, HTTPException, status
from sqlalchemy.orm import Session

app = FastAPI()
router = APIRouter(prefix="/api/v1/tickets", tags=["Support Tickets"])

# Diretório base configurado para armazenamento dos arquivos
UPLOAD_DIR = Path("/var/app/storage/tenants")

# Configurações de segurança do upload
MAX_FILE_SIZE_MB = 10
ALLOWED_MIME_TYPES = {
    "image/jpeg",
    "image/png",
    "application/pdf",
    "text/plain",
    "application/zip"
}

# --- Dependências simuladas de Autenticação e Banco ---

class UserContext:
    def __init__(self, user_id: str, tenant_id: str):
        self.user_id = user_id
        self.tenant_id = tenant_id

def get_current_user() -> UserContext:
    """
    Obtém o usuário autenticado a partir do token JWT (simulado).
    Garante que o tenant_id venha do contexto de autenticação seguro.
    """
    return UserContext(
        user_id="usr_987654321",
        tenant_id="tenant_123456789"
    )

def get_db():
    """Gerenciador de sessão do banco de dados (Dependency Injection)."""
    db = Session() # Instância da sessão do banco
    try:
        yield db
    finally:
        db.close()

# --- Rota de Upload ---

@router.post("/{ticket_id}/attachments", status_code=status.HTTP_201_CREATED)
async def upload_ticket_attachment(
    ticket_id: str,
    file: Annotated[UploadFile, File(...)],
    current_user: Annotated[UserContext, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)]):
    """
    Recebe um anexo para um chamado de suporte, salva em diretório isolado por tenant
    e registra o vínculo no banco de dados.
    """
    # 1. Validar Mime-Type
    if file.content_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tipo de arquivo não suportado: {file.content_type}"
        )

    # 2. Validar Tamanho do Arquivo (Stream em memória/chunk)
    file.file.seek(0, os.SEEK_END)
    file_size = file.file.tell()
    file.file.seek(0)  # Reseta o ponteiro de leitura

    if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"O arquivo excede o limite máximo de {MAX_FILE_SIZE_MB}MB."
        )

    # 3. Garantir isolamento por Tenant no armazenamento
    tenant_storage_path = UPLOAD_DIR / current_user.tenant_id / ticket_id
    tenant_storage_path.mkdir(parents=True, exist_ok=True)

    # 4. Gerar nome seguro para evitar File Path Traversal e colisão de nomes
    file_extension = Path(file.filename).suffix
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    destination_path = tenant_storage_path / unique_filename

    # 5. Salvar arquivo em disco de forma performática
    try:
        with destination_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha ao salvar o arquivo no servidor."
        ) from exc
    finally:
        file.file.close()

    # 6. Registrar o anexo no banco de dados
    attachment = Attachment(
        tenant_id=current_user.tenant_id,
        ticket_id=ticket_id,
        filename=unique_filename,
        original_filename=file.filename,
        file_path=str(destination_path),
        file_size=file_size,
        mime_type=file.content_type
    )

    db.add(attachment)
    db.commit()
    db.refresh(attachment)

    return {
        "id": attachment.id,
        "ticket_id": attachment.ticket_id,
        "original_filename": attachment.original_filename,
        "file_size": attachment.file_size,
        "created_at": attachment.created_at.isoformat()
    }

app.include_router(router)