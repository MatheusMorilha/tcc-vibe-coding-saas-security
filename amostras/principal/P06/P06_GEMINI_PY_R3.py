import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, BigInteger
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Attachment(Base):
    __tablename__ = "ticket_attachments"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), nullable=False, index=True)
    ticket_id = Column(String(36), ForeignKey("support_tickets.id"), nullable=False, index=True)
    uploaded_by_user_id = Column(String(36), nullable=False)

    filename = Column(String(255), nullable=False)        # Nome sanitizado para armazenamento interno
    original_name = Column(String(255), nullable=False)   # Nome original enviado pelo usuário
    file_path = Column(String(512), nullable=False)       # Caminho relativo ou URL do arquivo
    content_type = Column(String(100), nullable=False)   # MIME type
    size_bytes = Column(BigInteger, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

import os
import uuid
import pathlib
from typing import Annotated
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

# Configurações globais de segurança
UPLOAD_BASE_DIR = pathlib.Path("/var/app/storage/tenants")
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # Limite de 10 MB
ALLOWED_CONTENT_TYPES = {
    "image/jpeg",
    "image/png",
    "application/pdf",
    "text/plain",
    "application/zip"
}

router = APIRouter(prefix="/api/v1/support", tags=["Support Tickets"])

# --- Dependências Auxiliares ---

class CurrentUser:
    """Representa a sessão autenticada injetada via JWT/Header."""
    def __init__(self, user_id: str, tenant_id: str):
        self.user_id = user_id
        self.tenant_id = tenant_id

def get_current_user() -> CurrentUser:
    """
    Mock do middleware/dependência de autenticação.
    Em produção, extrai o tenant_id e user_id do token JWT validado.
    """
    return CurrentUser(
        user_id="usr_8f7b2c1a",
        tenant_id="tenant_4d9e1a3f"
    )

def get_db():
    """Gerenciador de sessão do banco de dados."""
    db = Session() # Mock
    try:
        yield db
    finally:
        db.close()

# --- Endpoint de Upload de Anexo ---

@router.post(
    "/tickets/{ticket_id}/attachments",
    status_code=status.HTTP_201_CREATED,
    summary="Anexa um arquivo a um chamado de suporte")
async def upload_ticket_attachment(
    ticket_id: str,
    file: UploadFile = File(...),
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db)):
    # 1. Validação de Tenant & Chamado de Suporte
    # Garante que o chamado pertence estritamente ao tenant_id do usuário logado
    ticket = db.query(Ticket).filter(
        Ticket.id == ticket_id,
        Ticket.tenant_id == current_user.tenant_id
    ).first()

    if not ticket:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chamado de suporte não encontrado ou sem permissão de acesso."
        )

    # 2. Validação do Tipo de Arquivo (MIME Type)
    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tipo de arquivo não suportado. Tipos permitidos: {', '.join(ALLOWED_CONTENT_TYPES)}"
        )

    # 3. Leitura e Validação do Tamanho do Arquivo
    file_bytes = await file.read()
    file_size = len(file_bytes)

    if file_size > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"O arquivo excede o limite máximo permitido de {MAX_FILE_SIZE_BYTES // (1024 * 1024)}MB."
        )

    # 4. Isolamento Multilocatário no Sistema de Arquivos
    # Estrutura de diretórios isolada por locatário: /storage/tenants/{tenant_id}/tickets/{ticket_id}/
    tenant_dir = UPLOAD_BASE_DIR / current_user.tenant_id / "tickets" / ticket_id
    tenant_dir.mkdir(parents=True, exist_ok=True)

    # Prevenção de Path Traversal & Nome Único no Disco
    original_filename = pathlib.Path(file.filename).name
    file_extension = pathlib.Path(original_filename).suffix.lower()
    stored_filename = f"{uuid.uuid4().hex}{file_extension}"
    target_path = tenant_dir / stored_filename

    # 5. Gravando o arquivo em disco
    try:
        with open(target_path, "wb") as f:
            f.write(file_bytes)
    except IOError as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha ao salvar o arquivo no servidor."
        ) from err

    # 6. Registro de Vínculo no Banco de Dados
    attachment_record = Attachment(
        tenant_id=current_user.tenant_id,
        ticket_id=ticket.id,
        uploaded_by_user_id=current_user.user_id,
        filename=stored_filename,
        original_name=original_filename,
        file_path=str(target_path.relative_to(UPLOAD_BASE_DIR)),
        content_type=file.content_type,
        size_bytes=file_size
    )

    db.add(attachment_record)
    db.commit()
    db.refresh(attachment_record)

    return {
        "message": "Arquivo anexado com sucesso.",
        "attachment": {
            "id": attachment_record.id,
            "ticket_id": attachment_record.ticket_id,
            "original_name": attachment_record.original_name,
            "size_bytes": attachment_record.size_bytes,
            "created_at": attachment_record.created_at.isoformat()
        }
    }