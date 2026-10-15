"""
Rota para cadastro/atualização das credenciais de ERP de uma empresa cliente.

Variáveis de ambiente (em produção, prefira KMS / Vault / Secrets Manager):
    ERP_CRED_KEYS        JSON {"1": "<chave AES-256 em base64>", "2": "..."}
    ERP_CRED_ACTIVE_KEY  versão da chave usada para novas cifragens (ex.: "1")
Gerar uma chave:  python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
"""
import base64
import ipaddress
import json
import logging
import os
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from sqlalchemy import DateTime, Integer, LargeBinary, String, UniqueConstraint, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("erp_credentials")


# --------------------------------------------------------------------------
# Dependências da aplicação (já existentes no projeto; aqui apenas o contrato)
# --------------------------------------------------------------------------
@dataclass
class CurrentUser:
    user_id: int
    tenant_id: int            # extraído do JWT/sessão validada, NUNCA do request body
    role: str                 # "admin", "member", ...
    subscription_active: bool


def get_current_user() -> CurrentUser:  # substituir pela dependência real de auth
    raise NotImplementedError


def get_db() -> Session:  # substituir pela dependência real de sessão
    raise NotImplementedError


# --------------------------------------------------------------------------
# Modelo
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class ErpCredential(Base):
    __tablename__ = "erp_credentials"
    __table_args__ = (UniqueConstraint("tenant_id", "erp_type", name="uq_tenant_erp"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    erp_type: Mapped[str] = mapped_column(String(32), nullable=False)
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    secret_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # senha/token cifrados
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    key_version: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_by: Mapped[int] = mapped_column(Integer, nullable=False)


# --------------------------------------------------------------------------
# Criptografia (AES-256-GCM com AAD vinculando o segredo ao tenant/ERP)
# --------------------------------------------------------------------------
def _keys() -> dict[str, bytes]:
    raw = json.loads(os.environ["ERP_CRED_KEYS"])
    return {v: base64.b64decode(k) for v, k in raw.items()}


def _aad(tenant_id: int, erp_type: str) -> bytes:
    # Impede que um registro cifrado seja "movido" para outro tenant e decifrado.
    return f"tenant:{tenant_id}|erp:{erp_type}".encode()


def encrypt_secret(plaintext: str, tenant_id: int, erp_type: str) -> tuple[bytes, bytes, str]:
    version = os.environ["ERP_CRED_ACTIVE_KEY"]
    nonce = os.urandom(12)
    ct = AESGCM(_keys()[version]).encrypt(nonce, plaintext.encode(), _aad(tenant_id, erp_type))
    return ct, nonce, version


def decrypt_secret(row: ErpCredential) -> str:
    key = _keys()[row.key_version]
    pt = AESGCM(key).decrypt(row.nonce, row.secret_ciphertext, _aad(row.tenant_id, row.erp_type))
    return pt.decode()


def load_credentials(db: Session, tenant_id: int, erp_type: str) -> Optional[dict]:
    """Uso exclusivo da rotina de integração (worker). Nunca expor via API."""
    row = db.scalar(
        select(ErpCredential).where(
            ErpCredential.tenant_id == tenant_id, ErpCredential.erp_type == erp_type
        )
    )
    if not row:
        return None
    return {"base_url": row.base_url, "username": row.username, "secret": decrypt_secret(row)}


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------
class ErpCredentialIn(BaseModel):
    model_config = ConfigDict(extra="forbid")  # rejeita campos inesperados (ex.: tenant_id)

    erp_type: Literal["sap", "totvs", "senior", "omie", "bling", "outro"]
    base_url: str = Field(max_length=512)
    username: str = Field(min_length=1, max_length=255)
    secret: SecretStr = Field(min_length=1, max_length=4096)  # senha ou token; SecretStr evita vazar em logs/repr

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        """Exige HTTPS e bloqueia destinos internos (mitiga SSRF na futura integração)."""
        parsed = urlparse(v.strip())
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("A URL do ERP deve usar HTTPS e conter um host válido.")
        if parsed.username or parsed.password:
            raise ValueError("Não inclua credenciais na URL.")
        try:
            infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            raise ValueError("Não foi possível resolver o host informado.")
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if not ip.is_global:  # loopback, privado, link-local (169.254.x.x / metadata), etc.
                raise ValueError("O host informado aponta para um endereço não permitido.")
        return v.strip().rstrip("/")


class ErpCredentialOut(BaseModel):
    erp_type: str
    base_url: str
    username: str
    secret_configured: bool = True  # o segredo jamais é devolvido
    updated_at: datetime


# --------------------------------------------------------------------------
# Rota
# --------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/integrations/erp", tags=["integrations"])


@router.put("/credentials", response_model=ErpCredentialOut, status_code=status.HTTP_200_OK)
def upsert_erp_credentials(
    payload: ErpCredentialIn,  # def síncrono: a resolução DNS do validador roda em threadpool
    user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # 1) Autorização: apenas administradores da empresa e com assinatura ativa.
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Apenas administradores podem gerenciar integrações.")
    if not user.subscription_active:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")

    # 2) Cifra o segredo (o tenant vem do contexto autenticado).
    ciphertext, nonce, key_version = encrypt_secret(
        payload.secret.get_secret_value(), user.tenant_id, payload.erp_type
    )
    now = datetime.now(timezone.utc)

    # 3) Upsert sempre filtrando por tenant_id.
    row = db.scalar(
        select(ErpCredential).where(
            ErpCredential.tenant_id == user.tenant_id,
            ErpCredential.erp_type == payload.erp_type,
        )
    )
    if row is None:
        row = ErpCredential(tenant_id=user.tenant_id, erp_type=payload.erp_type, created_at=now)
        db.add(row)

    row.base_url = payload.base_url
    row.username = payload.username
    row.secret_ciphertext = ciphertext
    row.nonce = nonce
    row.key_version = key_version
    row.updated_at = now
    row.updated_by = user.user_id

    try:
        db.commit()
    except IntegrityError:  # corrida entre duas requisições simultâneas do mesmo tenant
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Conflito ao salvar; tente novamente.")

    # 4) Auditoria sem dados sensíveis.
    logger.info(
        "erp_credentials_saved tenant_id=%s user_id=%s erp_type=%s",
        user.tenant_id, user.user_id, payload.erp_type,
    )

    return ErpCredentialOut(
        erp_type=row.erp_type, base_url=row.base_url, username=row.username, updated_at=row.updated_at
    )