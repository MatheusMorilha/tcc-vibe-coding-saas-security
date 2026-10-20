
import os
import uuid
from pathlib import Path

from fastapi import (
    FastAPI,
    Depends,
    File,
    HTTPException,
    UploadFile,
)
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    ForeignKey,
)
from sqlalchemy.orm import (
    declarative_base,
    sessionmaker,
    Session,
)

# Configuração
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./saas.db",
)
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./uploads")).resolve()
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

ALLOWED_EXTENSIONS = {
    ".pdf", ".png", ".jpg", ".jpeg", ".txt", ".docx"
}

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    connect_args=(
        {"check_same_thread": False}
        if DATABASE_URL.startswith("sqlite")
        else {}
    ),
)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,
)
Base = declarative_base()

app = FastAPI(title="API de Anexos de Suporte")


# Modelos simplificados
class Ticket(Base):
    __tablename__ = "tickets"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, nullable=False, index=True)
    title = Column(String, nullable=False)


class Attachment(Base):
    __tablename__ = "attachments"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, nullable=False, index=True)
    ticket_id = Column(
        Integer, ForeignKey("tickets.id"), nullable=False, index=True
    )
    uploaded_by = Column(Integer, nullable=False)
    original_filename = Column(String, nullable=False)
    stored_filename = Column(String, nullable=False, unique=True)
    storage_path = Column(String, nullable=False)
    content_type = Column(String, nullable=True)
    size_bytes = Column(Integer, nullable=False)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Substitua pela autenticação real via JWT ou sessão.
# Nunca aceite tenant_id diretamente do corpo da requisição.
def get_current_user():
    raise HTTPException(
        status_code=501,
        detail="Integre esta dependência à autenticação do sistema.",
    )


@app.post("/tickets/{ticket_id}/attachments", status_code=201)
async def upload_attachment(
    ticket_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    # A identidade autenticada deve fornecer:
    # current_user.id e current_user.tenant_id.
    tenant_id = current_user.tenant_id
    user_id = current_user.id

    # Verifica o chamado dentro do tenant do usuário.
    ticket = (
        db.query(Ticket)
        .filter(
            Ticket.id == ticket_id,
            Ticket.tenant_id == tenant_id,
        )
        .first()
    )

    if ticket is None:
        raise HTTPException(
            status_code=404,
            detail="Chamado não encontrado.",
        )

    # Verifique aqui também se o plano está ativo e se o
    # usuário possui permissão para anexar arquivos ao chamado.

    original_name = Path(file.filename or "").name
    extension = Path(original_name).suffix.lower()

    if not original_name or extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Tipo de arquivo não permitido.",
        )

    # Nome gerado pelo servidor, sem confiar no nome recebido.
    stored_name = f"{uuid.uuid4().hex}{extension}"
    tenant_dir = UPLOAD_DIR / str(tenant_id)
    tenant_dir.mkdir(parents=True, exist_ok=True)

    final_path = tenant_dir / stored_name
    temp_path = tenant_dir / f".{stored_name}.tmp"
    size = 0

    try:
        # Grava em blocos e limita o tamanho efetivamente recebido.
        with temp_path.open("xb") as destination:
            while True:
                chunk = await file.read(64 * 1024)

                if not chunk:
                    break

                size += len(chunk)

                if size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="O arquivo excede o limite de 10 MB.",
                    )

                destination.write(chunk)

        if size == 0:
            raise HTTPException(
                status_code=400,
                detail="O arquivo está vazio.",
            )

        # Publica o arquivo somente após concluir a gravação.
        os.replace(temp_path, final_path)

        attachment = Attachment(
            tenant_id=tenant_id,
            ticket_id=ticket.id,
            uploaded_by=user_id,
            original_filename=original_name,
            stored_filename=stored_name,
            storage_path=str(final_path),
            content_type=file.content_type,
            size_bytes=size,
        )

        db.add(attachment)
        db.commit()
        db.refresh(attachment)

        return {
            "message": "Anexo enviado com sucesso.",
            "attachment": {
                "id": attachment.id,
                "ticket_id": attachment.ticket_id,
                "filename": attachment.original_filename,
                "size_bytes": attachment.size_bytes,
                "content_type": attachment.content_type,
            },
        }

    except Exception:
        db.rollback()

        # Evita deixar arquivos órfãos quando a operação falha.
        final_path.unlink(missing_ok=True)
        raise

    finally:
        temp_path.unlink(missing_ok=True)
        await file.close()
