"""
Upload de anexos para chamados de suporte (SaaS multilocatário).

Princípios aplicados:
  * O tenant vem SEMPRE do usuário autenticado, nunca do corpo/URL da requisição.
  * O chamado é buscado filtrando por id E tenant_id (isolamento entre empresas).
  * Nome gravado em disco é gerado pelo servidor (UUID); o nome original é só metadado.
  * Tipo validado por allowlist de extensão + assinatura binária (magic bytes),
    sem confiar no Content-Type enviado pelo cliente.
  * Limite de tamanho aplicado durante a leitura em streaming (não carrega tudo em memória).
  * Gravação em arquivo temporário + rename atômico; rollback do arquivo se o banco falhar.
  * Limites do plano de assinatura (assinatura ativa, anexos por chamado, cota de armazenamento).
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import DateTime, ForeignKey, Integer, String, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

# Ajuste estes imports para a estrutura do seu projeto.
from app.db import Base
from app.deps import get_current_user, get_db  # get_current_user -> User autenticado
from app.models import Subscription, SupportTicket  # modelos já existentes

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/support/tickets", tags=["support"])

# --------------------------------------------------------------------------- #
# Configuração
# --------------------------------------------------------------------------- #
# Diretório FORA do document root / de qualquer pasta servida estaticamente.
STORAGE_ROOT = Path(os.environ.get("ATTACHMENTS_ROOT", "/var/lib/app/attachments")).resolve()
CHUNK_SIZE = 64 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB por arquivo

# Limites por plano: (anexos por chamado, cota total de armazenamento em bytes)
PLAN_LIMITS: dict[str, tuple[int, int]] = {
    "basic": (3, 500 * 1024 * 1024),
    "pro": (10, 5 * 1024 * 1024 * 1024),
    "enterprise": (30, 50 * 1024 * 1024 * 1024),
}

# extensão -> função de validação da assinatura binária
def _sig(*prefixes: bytes):
    return lambda head: any(head.startswith(p) for p in prefixes)

def _is_webp(head: bytes) -> bool:
    return head[:4] == b"RIFF" and head[8:12] == b"WEBP"

def _is_text(head: bytes) -> bool:
    return b"\x00" not in head

ALLOWED_TYPES = {
    ".pdf": ("application/pdf", _sig(b"%PDF-")),
    ".png": ("image/png", _sig(b"\x89PNG\r\n\x1a\n")),
    ".jpg": ("image/jpeg", _sig(b"\xff\xd8\xff")),
    ".jpeg": ("image/jpeg", _sig(b"\xff\xd8\xff")),
    ".gif": ("image/gif", _sig(b"GIF87a", b"GIF89a")),
    ".webp": ("image/webp", _is_webp),
    ".txt": ("text/plain", _is_text),
    ".csv": ("text/csv", _is_text),
    ".docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", _sig(b"PK\x03\x04")),
    ".xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", _sig(b"PK\x03\x04")),
}


# --------------------------------------------------------------------------- #
# Modelo (vínculo arquivo <-> chamado)
# --------------------------------------------------------------------------- #
class TicketAttachment(Base):
    __tablename__ = "ticket_attachments"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True, nullable=False)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("support_tickets.id"), index=True, nullable=False)
    uploaded_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)  # relativo ao STORAGE_ROOT
    content_type: Mapped[str] = mapped_column(String(127), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class AttachmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ticket_id: int
    original_filename: str
    content_type: str
    size_bytes: int
    sha256: str
    created_at: datetime


# --------------------------------------------------------------------------- #
# Funções auxiliares
# --------------------------------------------------------------------------- #
def sanitize_filename(raw: str | None) -> str:
    """Nome apenas para exibição: remove caminhos, controles e caracteres perigosos."""
    name = (raw or "arquivo").replace("\\", "/").split("/")[-1]
    name = unicodedata.normalize("NFKC", name)
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)
    name = re.sub(r"[^\w.\- ()]", "_", name, flags=re.UNICODE).strip(" .")
    return (name or "arquivo")[:255]


def build_storage_path(tenant_id: int, ticket_id: int, ext: str) -> tuple[Path, str]:
    """Caminho absoluto + relativo, sempre dentro de STORAGE_ROOT."""
    rel = Path(str(tenant_id)) / str(ticket_id) / f"{uuid.uuid4().hex}{ext}"
    abs_path = (STORAGE_ROOT / rel).resolve()
    if STORAGE_ROOT not in abs_path.parents:  # defesa extra contra path traversal
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Caminho de armazenamento inválido.")
    return abs_path, rel.as_posix()


def stream_to_disk(upload: UploadFile, dest: Path) -> tuple[int, str, bytes, Path]:
    """
    Grava o upload em arquivo temporário, aplicando o limite de tamanho em streaming.
    Retorna (tamanho, sha256, primeiros bytes, caminho do temporário). O chamador
    valida o conteúdo e só então publica com os.replace(tmp, dest).
    """
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    tmp = dest.with_suffix(dest.suffix + ".part")
    digest = hashlib.sha256()
    total = 0
    head = b""
    try:
        with open(tmp, "wb") as out:
            while chunk := upload.file.read(CHUNK_SIZE):
                total += len(chunk)
                if total > MAX_FILE_BYTES:
                    raise HTTPException(
                        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        f"Arquivo excede o limite de {MAX_FILE_BYTES // (1024 * 1024)} MB.",
                    )
                if len(head) < 8192:
                    head += chunk[: 8192 - len(head)]
                digest.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        if total == 0:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Arquivo vazio.")
        os.chmod(tmp, 0o640)
        return total, digest.hexdigest(), head, tmp
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #
@router.post(
    "/{ticket_id}/attachments",
    response_model=AttachmentOut,
    status_code=status.HTTP_201_CREATED,
)
def upload_ticket_attachment(
    ticket_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    tenant_id = current_user.tenant_id  # NUNCA aceitar tenant_id do cliente

    # 1) Chamado precisa existir E pertencer ao tenant do usuário.
    #    404 (e não 403) para não revelar a existência de chamados de outras empresas.
    ticket = db.execute(
        select(SupportTicket).where(
            SupportTicket.id == ticket_id,
            SupportTicket.tenant_id == tenant_id,
        )
    ).scalar_one_or_none()
    if ticket is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Chamado não encontrado.")

    # 2) Autorização dentro do tenant: autor do chamado ou perfil de suporte/admin.
    if ticket.created_by != current_user.id and not current_user.has_any_role("support", "admin"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Chamado não encontrado.")

    if ticket.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Chamado encerrado não aceita anexos.")

    # 3) Assinatura ativa e limites do plano.
    sub = db.execute(
        select(Subscription).where(Subscription.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if sub is None or sub.status != "active":
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")
    max_per_ticket, quota_bytes = PLAN_LIMITS.get(sub.plan_code, PLAN_LIMITS["basic"])

    count = db.scalar(
        select(func.count(TicketAttachment.id)).where(
            TicketAttachment.tenant_id == tenant_id,
            TicketAttachment.ticket_id == ticket_id,
        )
    )
    if count >= max_per_ticket:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"Seu plano permite até {max_per_ticket} anexos por chamado.",
        )
    used = db.scalar(
        select(func.coalesce(func.sum(TicketAttachment.size_bytes), 0)).where(
            TicketAttachment.tenant_id == tenant_id
        )
    )

    # 4) Extensão permitida (allowlist).
    display_name = sanitize_filename(file.filename)
    ext = Path(display_name).suffix.lower()
    if ext not in ALLOWED_TYPES:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Tipo de arquivo não permitido.")
    content_type, signature_ok = ALLOWED_TYPES[ext]

    # 5) Grava em streaming com limite de tamanho.
    dest, rel_path = build_storage_path(tenant_id, ticket_id, ext)
    size, sha256, head, tmp = stream_to_disk(file, dest)

    try:
        # 6) Conteúdo real precisa corresponder à extensão; cota do tenant.
        if not signature_ok(head):
            raise HTTPException(
                status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                "O conteúdo do arquivo não corresponde à extensão informada.",
            )
        if used + size > quota_bytes:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "Cota de armazenamento do plano excedida."
            )

        os.replace(tmp, dest)  # publica o arquivo de forma atômica

        # 7) Registra o vínculo arquivo <-> chamado.
        attachment = TicketAttachment(
            tenant_id=tenant_id,
            ticket_id=ticket_id,
            uploaded_by=current_user.id,
            original_filename=display_name,
            storage_path=rel_path,
            content_type=content_type,  # derivado da allowlist, não do cliente
            size_bytes=size,
            sha256=sha256,
        )
        db.add(attachment)
        try:
            db.commit()
        except Exception:
            db.rollback()
            dest.unlink(missing_ok=True)  # não deixa arquivo órfão
            logger.exception("Falha ao registrar anexo (tenant=%s ticket=%s)", tenant_id, ticket_id)
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Erro ao salvar o anexo.")
        db.refresh(attachment)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    logger.info(
        "Anexo %s gravado (tenant=%s ticket=%s user=%s size=%s)",
        attachment.id, tenant_id, ticket_id, current_user.id, size,
    )
    return attachment