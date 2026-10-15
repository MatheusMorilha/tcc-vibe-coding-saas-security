"""
Rota de upload de anexo para chamados de suporte (SaaS multilocatário).

POST /api/v1/tickets/{ticket_id}/attachments

Princípios de segurança aplicados:
- O tenant vem SEMPRE da sessão autenticada, nunca do cliente (corpo, query ou header).
- O chamado é buscado filtrando por (id, tenant_id): chamado de outra empresa
  é indistinguível de chamado inexistente (404), evitando IDOR e enumeração.
- O nome original do arquivo nunca é usado como caminho em disco; o arquivo é
  gravado com UUID, em diretório particionado por tenant, fora da raiz pública.
- Limite de tamanho aplicado durante o streaming (não confia em Content-Length).
- Tipo validado por extensão em allowlist + assinatura (magic bytes), não pelo
  Content-Type informado pelo cliente.
- Verificação do plano de assinatura (ativo, anexos permitidos, cota de armazenamento).
- Gravação atômica (arquivo temporário -> os.replace) e limpeza em caso de falha.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Configuração
# --------------------------------------------------------------------------- #

# Diretório FORA do document root / de qualquer pasta servida estaticamente.
UPLOAD_ROOT = Path(os.environ.get("UPLOAD_ROOT", "/var/lib/saas/uploads")).resolve()

CHUNK_SIZE = 1024 * 1024  # 1 MiB
HARD_MAX_FILE_SIZE = 25 * 1024 * 1024  # teto global; o plano pode ser mais restritivo

# extensão -> (content-type canônico, validador de conteúdo)
def _is_pdf(head: bytes) -> bool:
    return head.startswith(b"%PDF-")

def _is_png(head: bytes) -> bool:
    return head.startswith(b"\x89PNG\r\n\x1a\n")

def _is_jpeg(head: bytes) -> bool:
    return head.startswith(b"\xff\xd8\xff")

def _is_text(head: bytes) -> bool:
    if b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as exc:
        # Pode ter cortado um caractere multibyte no limite do buffer.
        if exc.start < len(head) - 4:
            return False
    return True

ALLOWED_TYPES = {
    ".pdf": ("application/pdf", _is_pdf),
    ".png": ("image/png", _is_png),
    ".jpg": ("image/jpeg", _is_jpeg),
    ".jpeg": ("image/jpeg", _is_jpeg),
    ".txt": ("text/plain", _is_text),
    ".log": ("text/plain", _is_text),
}


# --------------------------------------------------------------------------- #
# Modelos (todas as tabelas carregam tenant_id; mesma base para todas as empresas)
# --------------------------------------------------------------------------- #

class Base(DeclarativeBase):
    pass


class Plan(Base):
    __tablename__ = "plans"
    id: Mapped[int] = mapped_column(primary_key=True)
    allow_ticket_attachments: Mapped[bool] = mapped_column(default=True)
    max_attachment_bytes: Mapped[int] = mapped_column(BigInteger, default=10 * 1024 * 1024)
    storage_quota_bytes: Mapped[int] = mapped_column(BigInteger, default=1024**3)


class Subscription(Base):
    __tablename__ = "subscriptions"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(index=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("plans.id"))
    status: Mapped[str] = mapped_column(String(20))  # active | past_due | canceled ...
    current_period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Ticket(Base):
    __tablename__ = "tickets"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(index=True)
    created_by: Mapped[int] = mapped_column()
    status: Mapped[str] = mapped_column(String(20))  # open | in_progress | closed ...


class TicketAttachment(Base):
    __tablename__ = "ticket_attachments"
    __table_args__ = (Index("ix_att_tenant_ticket", "tenant_id", "ticket_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[int] = mapped_column()
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id"))
    uploaded_by: Mapped[int] = mapped_column()
    original_filename: Mapped[str] = mapped_column(String(255))  # apenas para exibição
    storage_key: Mapped[str] = mapped_column(String(255), unique=True)  # relativo a UPLOAD_ROOT
    content_type: Mapped[str] = mapped_column(String(100))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# --------------------------------------------------------------------------- #
# Dependências (substitua pelos equivalentes da sua aplicação)
# --------------------------------------------------------------------------- #

class CurrentUser(BaseModel):
    id: int
    tenant_id: int
    is_active: bool = True


def get_db() -> Iterator[Session]:
    """Fornece uma Session SQLAlchemy por requisição."""
    raise NotImplementedError("Conectar ao session factory da aplicação")


def get_current_user(request: Request) -> CurrentUser:
    """Resolve o usuário autenticado (JWT/sessão). tenant_id vem do token/sessão."""
    raise NotImplementedError("Conectar ao mecanismo de autenticação da aplicação")


# --------------------------------------------------------------------------- #
# Schema de resposta
# --------------------------------------------------------------------------- #

class AttachmentOut(BaseModel):
    id: uuid.UUID
    ticket_id: int
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    created_at: datetime

    model_config = {"from_attributes": True}


# --------------------------------------------------------------------------- #
# Utilitários
# --------------------------------------------------------------------------- #

_UNSAFE_CHARS = re.compile(r"[^\w.\- ()]", re.UNICODE)


def sanitize_display_name(raw: str | None) -> str:
    """Nome apenas para exibição: remove caminhos, controles e caracteres perigosos."""
    name = (raw or "arquivo").replace("\\", "/").split("/")[-1]
    name = _UNSAFE_CHARS.sub("_", name).strip(" .") or "arquivo"
    return name[:255]


def get_active_plan(db: Session, tenant_id: int) -> Plan:
    now = datetime.now(timezone.utc)
    row = db.execute(
        select(Plan)
        .join(Subscription, Subscription.plan_id == Plan.id)
        .where(
            Subscription.tenant_id == tenant_id,
            Subscription.status == "active",
            Subscription.current_period_end > now,
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")
    return row


def tenant_storage_used(db: Session, tenant_id: int) -> int:
    return db.execute(
        select(func.coalesce(func.sum(TicketAttachment.size_bytes), 0)).where(
            TicketAttachment.tenant_id == tenant_id
        )
    ).scalar_one()


def _safe_path(storage_key: str) -> Path:
    """Garante que o caminho final permanece dentro de UPLOAD_ROOT."""
    path = (UPLOAD_ROOT / storage_key).resolve()
    if UPLOAD_ROOT not in path.parents:
        raise ValueError("Caminho de armazenamento inválido")
    return path


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #

router = APIRouter(prefix="/api/v1/tickets", tags=["tickets"])


@router.post(
    "/{ticket_id}/attachments",
    response_model=AttachmentOut,
    status_code=status.HTTP_201_CREATED,
)
def upload_ticket_attachment(
    ticket_id: int,
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    # (endpoint síncrono: o FastAPI o executa em threadpool, então a E/S de
    #  disco abaixo não bloqueia o event loop)

    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Usuário inativo.")

    # 1) Chamado: sempre filtrado pelo tenant da sessão. 404 uniforme.
    ticket = db.execute(
        select(Ticket).where(Ticket.id == ticket_id, Ticket.tenant_id == user.tenant_id)
    ).scalar_one_or_none()
    if ticket is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Chamado não encontrado.")
    if ticket.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Chamado encerrado não aceita anexos.")

    # (opcional) regra de papel: ex.: apenas autor ou membro de suporte da empresa
    # if not user_can_comment_on_ticket(db, user, ticket): raise HTTPException(403, ...)

    # 2) Plano de assinatura
    plan = get_active_plan(db, user.tenant_id)
    if not plan.allow_ticket_attachments:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Seu plano não permite anexos.")
    max_size = min(plan.max_attachment_bytes, HARD_MAX_FILE_SIZE)
    remaining_quota = plan.storage_quota_bytes - tenant_storage_used(db, user.tenant_id)
    if remaining_quota <= 0:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Cota de armazenamento esgotada.")
    limit = min(max_size, remaining_quota)

    # 3) Rejeição antecipada por Content-Length (otimização; o limite real é no streaming)
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit + 64 * 1024:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Arquivo muito grande.")

    # 4) Extensão em allowlist
    display_name = sanitize_display_name(file.filename)
    ext = Path(display_name).suffix.lower()
    if ext not in ALLOWED_TYPES:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Tipo de arquivo não permitido.")
    canonical_type, content_check = ALLOWED_TYPES[ext]

    # 5) Grava em arquivo temporário, em streaming, com limite e hash
    attachment_id = uuid.uuid4()
    storage_key = f"tenant_{user.tenant_id}/ticket_{ticket.id}/{attachment_id.hex}{ext}"
    final_path = _safe_path(storage_key)
    tmp_path = final_path.with_suffix(final_path.suffix + ".part")
    final_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)

    sha256 = hashlib.sha256()
    size = 0
    head = b""

    try:
        # O_EXCL impede sobrescrever; 0o640 evita leitura por outros usuários do SO.
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = file.file.read(CHUNK_SIZE)
                if not chunk:
                    break
                if size == 0:
                    head = chunk[:4096]
                size += len(chunk)
                if size > limit:
                    raise HTTPException(
                        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        "Arquivo excede o limite permitido pelo seu plano.",
                    )
                sha256.update(chunk)
                out.write(chunk)

        if size == 0:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Arquivo vazio.")
        if not content_check(head):
            raise HTTPException(
                status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                "O conteúdo do arquivo não corresponde à extensão informada.",
            )

        # 6) Move para o destino final e registra o vínculo
        os.replace(tmp_path, final_path)

        attachment = TicketAttachment(
            id=attachment_id,
            tenant_id=user.tenant_id,
            ticket_id=ticket.id,
            uploaded_by=user.id,
            original_filename=display_name,
            storage_key=storage_key,
            content_type=canonical_type,  # tipo canônico, não o enviado pelo cliente
            size_bytes=size,
            sha256=sha256.hexdigest(),
        )
        db.add(attachment)
        db.commit()
        db.refresh(attachment)

    except HTTPException:
        db.rollback()
        _cleanup(tmp_path, final_path)
        raise
    except Exception:
        db.rollback()
        _cleanup(tmp_path, final_path)
        logger.exception(
            "Falha ao salvar anexo (tenant=%s, ticket=%s, user=%s)",
            user.tenant_id, ticket_id, user.id,
        )
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Não foi possível salvar o anexo.")
    finally:
        file.file.close()

    logger.info(
        "Anexo %s gravado (tenant=%s, ticket=%s, user=%s, bytes=%s)",
        attachment.id, user.tenant_id, ticket.id, user.id, size,
    )

    return AttachmentOut(
        id=attachment.id,
        ticket_id=attachment.ticket_id,
        filename=attachment.original_filename,
        content_type=attachment.content_type,
        size_bytes=attachment.size_bytes,
        sha256=attachment.sha256,
        created_at=attachment.created_at,
    )


def _cleanup(*paths: Path) -> None:
    """Remove arquivos parciais/órfãos sem mascarar o erro original."""
    for p in paths:
        try:
            p.unlink(missing_ok=True)
        except OSError:
            logger.warning("Não foi possível remover %s", p)