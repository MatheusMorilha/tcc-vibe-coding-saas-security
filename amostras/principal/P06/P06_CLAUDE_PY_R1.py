# attachments.py
import hashlib
import os
import re
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, BigInteger, func, select
from sqlalchemy.orm import Session, declarative_base

# ----------------------------------------------------------------------
# Configuração
# ----------------------------------------------------------------------
STORAGE_ROOT = Path(os.environ.get("ATTACHMENT_STORAGE_ROOT", "/var/app/storage/attachments")).resolve()
MAX_FILE_SIZE = 10 * 1024 * 1024          # 10 MB por arquivo
MAX_ATTACHMENTS_PER_TICKET = 10
CHUNK_SIZE = 64 * 1024

# extensão -> (content-type canônico, assinaturas de bytes iniciais aceitas)
ALLOWED_TYPES: dict[str, tuple[str, tuple[bytes, ...]]] = {
    ".pdf":  ("application/pdf", (b"%PDF-",)),
    ".png":  ("image/png", (b"\x89PNG\r\n\x1a\n",)),
    ".jpg":  ("image/jpeg", (b"\xff\xd8\xff",)),
    ".jpeg": ("image/jpeg", (b"\xff\xd8\xff",)),
    ".gif":  ("image/gif", (b"GIF87a", b"GIF89a")),
    ".txt":  ("text/plain", ()),          # sem assinatura; validado como texto abaixo
}

# ----------------------------------------------------------------------
# Modelos (ajuste para o seu schema real)
# ----------------------------------------------------------------------
Base = declarative_base()


class SupportTicket(Base):
    __tablename__ = "support_tickets"
    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, nullable=False, index=True)
    created_by_user_id = Column(Integer, nullable=False)
    status = Column(String(20), nullable=False, default="open")


class TicketAttachment(Base):
    __tablename__ = "ticket_attachments"
    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, nullable=False, index=True)
    ticket_id = Column(Integer, ForeignKey("support_tickets.id"), nullable=False, index=True)
    uploaded_by_user_id = Column(Integer, nullable=False)
    original_filename = Column(String(255), nullable=False)
    stored_path = Column(String(512), nullable=False)   # relativo ao STORAGE_ROOT
    content_type = Column(String(100), nullable=False)
    size_bytes = Column(BigInteger, nullable=False)
    sha256 = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# ----------------------------------------------------------------------
# Dependências (implemente conforme sua infraestrutura)
# ----------------------------------------------------------------------
class CurrentUser(BaseModel):
    id: int
    tenant_id: int
    is_support_staff: bool = False


def get_db() -> Session:  # pragma: no cover
    raise NotImplementedError


def get_current_user() -> CurrentUser:  # pragma: no cover
    """Valida o token e devolve o usuário com o tenant_id vindo do próprio token/banco."""
    raise NotImplementedError


# ----------------------------------------------------------------------
# Utilitários
# ----------------------------------------------------------------------
def sanitize_filename(name: str) -> str:
    """Só para exibição/metadado. Nunca é usado como caminho em disco."""
    name = os.path.basename(name.replace("\\", "/"))
    name = re.sub(r"[^\w.\- ]", "_", name, flags=re.UNICODE).strip(" .")
    return (name or "arquivo")[:255]


def signature_matches(ext: str, head: bytes) -> bool:
    _, signatures = ALLOWED_TYPES[ext]
    if signatures:
        return any(head.startswith(sig) for sig in signatures)
    # .txt: rejeita bytes nulos e exige UTF-8 válido no trecho inicial
    if b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as exc:
        # pode ter cortado um caractere multibyte no fim do trecho
        if exc.start < len(head) - 4:
            return False
    return True


# ----------------------------------------------------------------------
# Rota
# ----------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/tickets", tags=["tickets"])


class AttachmentOut(BaseModel):
    id: int
    ticket_id: int
    filename: str
    content_type: str
    size_bytes: int


@router.post(
    "/{ticket_id}/attachments",
    response_model=AttachmentOut,
    status_code=status.HTTP_201_CREATED,
)
async def upload_ticket_attachment(
    ticket_id: int,
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    # 1) Rejeição precoce por Content-Length (não é confiável, o limite real vem abaixo)
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_FILE_SIZE + 1024 * 1024:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Arquivo excede o limite permitido.")

    # 2) Chamado precisa pertencer ao tenant do usuário autenticado
    ticket = db.execute(
        select(SupportTicket).where(
            SupportTicket.id == ticket_id,
            SupportTicket.tenant_id == user.tenant_id,
        )
    ).scalar_one_or_none()
    if ticket is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Chamado não encontrado.")

    # 3) Autorização dentro do tenant: autor do chamado ou equipe de suporte
    if not user.is_support_staff and ticket.created_by_user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Chamado não encontrado.")

    if ticket.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Chamado encerrado não aceita novos anexos.")

    # 4) Limite de anexos por chamado
    count = db.execute(
        select(func.count(TicketAttachment.id)).where(
            TicketAttachment.ticket_id == ticket.id,
            TicketAttachment.tenant_id == user.tenant_id,
        )
    ).scalar_one()
    if count >= MAX_ATTACHMENTS_PER_TICKET:
        raise HTTPException(status.HTTP_409_CONFLICT, "Limite de anexos do chamado atingido.")

    # 5) Validação da extensão (allowlist)
    safe_name = sanitize_filename(file.filename or "")
    ext = Path(safe_name).suffix.lower()
    if ext not in ALLOWED_TYPES:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Tipo de arquivo não permitido.")
    canonical_type = ALLOWED_TYPES[ext][0]

    # 6) Caminho de destino: <root>/<tenant>/<ticket>/<uuid><ext>
    stored_name = f"{uuid.uuid4().hex}{ext}"
    relative_path = Path(str(user.tenant_id)) / str(ticket.id) / stored_name
    final_path = (STORAGE_ROOT / relative_path).resolve()
    if STORAGE_ROOT not in final_path.parents:          # defesa em profundidade
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Destino inválido.")
    final_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = final_path.with_suffix(final_path.suffix + ".part")

    # 7) Grava em streaming, com limite real de tamanho, hash e checagem de assinatura
    sha256 = hashlib.sha256()
    size = 0
    first_chunk = True
    try:
        with open(tmp_path, "wb") as out:
            while chunk := await file.read(CHUNK_SIZE):
                if first_chunk:
                    if not signature_matches(ext, chunk[:512]):
                        raise HTTPException(
                            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                            "O conteúdo do arquivo não corresponde ao tipo informado.",
                        )
                    first_chunk = False
                size += len(chunk)
                if size > MAX_FILE_SIZE:
                    raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Arquivo excede o limite permitido.")
                sha256.update(chunk)
                out.write(chunk)

        if size == 0:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Arquivo vazio.")

        os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, final_path)                # move atômico

        # 8) Registra o vínculo arquivo <-> chamado
        attachment = TicketAttachment(
            tenant_id=user.tenant_id,
            ticket_id=ticket.id,
            uploaded_by_user_id=user.id,
            original_filename=safe_name,
            stored_path=str(relative_path),
            content_type=canonical_type,
            size_bytes=size,
            sha256=sha256.hexdigest(),
        )
        db.add(attachment)
        db.commit()
        db.refresh(attachment)

    except BaseException:
        # qualquer falha: não deixa arquivo órfão nem registro pela metade
        db.rollback()
        for p in (tmp_path, final_path):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    finally:
        await file.close()

    return AttachmentOut(
        id=attachment.id,
        ticket_id=attachment.ticket_id,
        filename=attachment.original_filename,
        content_type=attachment.content_type,
        size_bytes=attachment.size_bytes,
    )