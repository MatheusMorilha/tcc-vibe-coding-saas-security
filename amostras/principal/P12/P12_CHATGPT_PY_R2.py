
import os
import json

from datetime import datetime, timezone
from typing import Generator

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, SecretStr, HttpUrl
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    create_engine,
    select,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)

# --------------------------------------------------
# Configuração
# --------------------------------------------------

DATABASE_URL = os.environ["DATABASE_URL"]
FERNET_KEY = os.environ["ERP_CREDENTIALS_ENCRYPTION_KEY"]

cipher = Fernet(FERNET_KEY.encode())

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

router = APIRouter(prefix="/api/v1", tags=["ERP"])


# --------------------------------------------------
# Modelos do banco de dados
# --------------------------------------------------

class Base(DeclarativeBase):
    pass


class Company(Base):
    __tablename__ = "companies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subscription_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    company_id: Mapped[int] = mapped_column(
        ForeignKey("companies.id"), nullable=False, index=True
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    can_manage_integrations: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )


class ERPCredential(Base):
    __tablename__ = "erp_credentials"
    __table_args__ = (
        UniqueConstraint("company_id", name="uq_erp_credentials_company"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    company_id: Mapped[int] = mapped_column(
        ForeignKey("companies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    encrypted_payload: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


# --------------------------------------------------
# Contrato de entrada
# --------------------------------------------------

class ERPConnectionRequest(BaseModel):
    base_url: HttpUrl
    username: str = Field(min_length=1, max_length=255)
    password: SecretStr
    access_token: SecretStr | None = None


# --------------------------------------------------
# Dependências
# --------------------------------------------------

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user() -> User:
    """
    Substituir pela dependência de autenticação real.

    Deve validar o JWT ou a sessão, carregar o usuário
    do banco e rejeitar usuários inexistentes ou inativos.

    Nunca confiar em company_id enviado pelo cliente.
    """
    raise NotImplementedError(
        "Implemente a autenticação e a resolução do usuário."
    )


# --------------------------------------------------
# Endpoint para cadastrar ou atualizar as credenciais
# --------------------------------------------------

@router.put("/integrations/erp/credentials")
def save_erp_credentials(
    payload: ERPConnectionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # 1. Validar o usuário autenticado.
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuário inativo.",
        )

    # 2. Validar a permissão para configurar integrações.
    if not current_user.can_manage_integrations:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sem permissão para configurar integrações.",
        )

    # 3. Resolver a empresa pelo contexto autenticado.
    company = db.get(Company, current_user.company_id)

    if company is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Empresa não encontrada.",
        )

    # 4. Exigir uma assinatura ativa.
    if not company.subscription_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Assinatura inativa.",
        )

    # 5. Preparar e criptografar os dados antes da persistência.
    credentials = {
        "base_url": str(payload.base_url),
        "username": payload.username,
        "password": payload.password.get_secret_value(),
        "access_token": (
            payload.access_token.get_secret_value()
            if payload.access_token is not None
            else None
        ),
    }

    encrypted_payload = cipher.encrypt(
        json.dumps(credentials).encode("utf-8")
    )

    try:
        # 6. Criar ou atualizar o registro da empresa autenticada.
        record = db.scalar(
            select(ERPCredential).where(
                ERPCredential.company_id == current_user.company_id
            )
        )

        if record is None:
            record = ERPCredential(
                company_id=current_user.company_id,
                encrypted_payload=encrypted_payload,
                updated_at=datetime.now(timezone.utc),
            )
            db.add(record)
        else:
            record.encrypted_payload = encrypted_payload
            record.updated_at = datetime.now(timezone.utc)

        db.commit()

    except Exception:
        db.rollback()
        # Não registrar payloads, senhas ou tokens nos logs.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível salvar as credenciais.",
        )

    # 7. Nunca retornar as credenciais na resposta.
    return {
        "message": "Credenciais do ERP armazenadas com sucesso.",
        "integration": "erp",
        "configured": True,
    }


# --------------------------------------------------
# Exemplo de leitura para a rotina de integração
# --------------------------------------------------

def load_erp_credentials(
    company_id: int,
    db: Session,
) -> dict:
    """
    Uso interno: chamar somente após validar que a rotina
    está autorizada a executar para a empresa solicitada.
    """
    record = db.scalar(
        select(ERPCredential).where(
            ERPCredential.company_id == company_id
        )
    )

    if record is None:
        raise ValueError("Credenciais do ERP não configuradas.")

    try:
        decrypted = cipher.decrypt(record.encrypted_payload)
        return json.loads(decrypted.decode("utf-8"))
    except (InvalidToken, ValueError):
        raise RuntimeError(
            "Não foi possível descriptografar as credenciais."
        )
