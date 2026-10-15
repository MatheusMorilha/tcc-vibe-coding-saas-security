# erp_credentials.py
from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field, SecretStr, field_validator
from sqlalchemy import DateTime, LargeBinary, String, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("integrations.erp")


# ----------------------------------------------------------------------
# Modelos
# ----------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class ERPCredential(Base):
    __tablename__ = "erp_credentials"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # unique => no máximo uma configuração de ERP por empresa
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), unique=True, index=True, nullable=False
    )
    erp_type: Mapped[str] = mapped_column(String(50), nullable=False)
    base_url: Mapped[str] = mapped_column(String(500), nullable=False)
    username_hint: Mapped[str] = mapped_column(String(10), nullable=False)  # só para exibição mascarada
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


# ----------------------------------------------------------------------
# Criptografia (AES-256-GCM com AAD = tenant_id)
# ----------------------------------------------------------------------
class KeyRing:
    """
    Em produção, carregue as chaves de um KMS/Secret Manager (AWS KMS, GCP KMS,
    Vault) usando envelope encryption. Aqui as chaves vêm de variáveis de ambiente:
      ERP_KEY_V1=<32 bytes em hex>, ERP_KEY_CURRENT=1
    """

    def __init__(self) -> None:
        self.current = int(os.environ["ERP_KEY_CURRENT"])

    def get(self, version: int) -> bytes:
        key = bytes.fromhex(os.environ[f"ERP_KEY_V{version}"])
        if len(key) != 32:
            raise RuntimeError("Chave de criptografia inválida (esperado 32 bytes).")
        return key


keyring = KeyRing()


def encrypt_credentials(tenant_id: uuid.UUID, payload: dict) -> tuple[bytes, bytes, int]:
    version = keyring.current
    nonce = os.urandom(12)  # nunca reutilizar nonce com a mesma chave
    plaintext = json.dumps(payload, separators=(",", ":")).encode()
    ct = AESGCM(keyring.get(version)).encrypt(nonce, plaintext, tenant_id.bytes)
    return nonce, ct, version


def decrypt_credentials(record: ERPCredential) -> dict:
    """Uso exclusivo da rotina de integração (nunca expor em rota de API)."""
    pt = AESGCM(keyring.get(record.key_version)).decrypt(
        record.nonce, record.ciphertext, record.tenant_id.bytes
    )
    return json.loads(pt)


# ----------------------------------------------------------------------
# Dependências (ajuste para o seu mecanismo de autenticação)
# ----------------------------------------------------------------------
class CurrentUser(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    role: str  # "admin" | "member" ...


def get_db() -> Session: ...                # sua sessão do SQLAlchemy
def get_current_user() -> CurrentUser: ...  # valida o JWT/sessão e extrai tenant_id do token
def tenant_has_feature(db: Session, tenant_id: uuid.UUID, feature: str) -> bool: ...  # consulta o plano ativo
def write_audit_log(db: Session, **kwargs) -> None: ...


def require_tenant_admin(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente.")
    return user


# ----------------------------------------------------------------------
# Schemas
# ----------------------------------------------------------------------
ALLOWED_ERPS = {"sap_b1", "totvs_protheus", "senior", "omie", "bling"}


def _assert_public_https_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("A URL do ERP deve usar HTTPS.")
    if parsed.username or parsed.password:
        raise ValueError("A URL não pode conter credenciais embutidas.")
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError("Não foi possível resolver o host informado.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:  # bloqueia privado, loopback, link-local, metadata cloud etc.
            raise ValueError("Host não permitido.")
    return url.rstrip("/")


class ERPCredentialsIn(BaseModel):
    model_config = {"extra": "forbid"}  # rejeita campos inesperados (ex.: tenant_id)

    erp_type: str
    base_url: str = Field(max_length=500)
    username: str = Field(min_length=1, max_length=200)
    password: SecretStr = Field(min_length=1, max_length=500)
    api_token: SecretStr | None = Field(default=None, max_length=2000)

    @field_validator("erp_type")
    @classmethod
    def _erp_type(cls, v: str) -> str:
        if v not in ALLOWED_ERPS:
            raise ValueError("ERP não suportado.")
        return v

    @field_validator("base_url")
    @classmethod
    def _base_url(cls, v: str) -> str:
        return _assert_public_https_url(v)


class ERPCredentialsOut(BaseModel):
    """Nunca devolve segredos."""
    erp_type: str
    base_url: str
    username_masked: str
    updated_at: datetime


def _mask(value: str) -> str:
    return value[:2] + "***" if len(value) > 2 else "***"


# ----------------------------------------------------------------------
# Rota
# ----------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/integrations/erp", tags=["integrations"])


@router.put("/credentials", response_model=ERPCredentialsOut, status_code=status.HTTP_200_OK)
def upsert_erp_credentials(
    body: ERPCredentialsIn,
    response: Response,
    user: CurrentUser = Depends(require_tenant_admin),
    db: Session = Depends(get_db),
) -> ERPCredentialsOut:
    response.headers["Cache-Control"] = "no-store"

    # Plano ativo com direito a integrações
    if not tenant_has_feature(db, user.tenant_id, "erp_integration"):
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Seu plano não inclui integração com ERP.")

    secret_payload = {
        "username": body.username,
        "password": body.password.get_secret_value(),
        "api_token": body.api_token.get_secret_value() if body.api_token else None,
    }
    nonce, ciphertext, key_version = encrypt_credentials(user.tenant_id, secret_payload)
    now = datetime.now(timezone.utc)

    # A consulta é SEMPRE filtrada pelo tenant do token
    record = db.query(ERPCredential).filter(ERPCredential.tenant_id == user.tenant_id).one_or_none()
    action = "erp_credentials.updated"
    if record is None:
        action = "erp_credentials.created"
        record = ERPCredential(tenant_id=user.tenant_id)
        db.add(record)

    record.erp_type = body.erp_type
    record.base_url = body.base_url
    record.username_hint = _mask(body.username)
    record.nonce = nonce
    record.ciphertext = ciphertext
    record.key_version = key_version
    record.updated_by = user.id
    record.updated_at = now

    # Auditoria: quem, quando, o quê. Jamais o conteúdo dos segredos.
    write_audit_log(
        db, tenant_id=user.tenant_id, user_id=user.id, action=action,
        metadata={"erp_type": body.erp_type, "base_url": body.base_url, "key_version": key_version},
    )
    db.commit()

    logger.info("ERP credentials %s tenant=%s user=%s", action, user.tenant_id, user.id)

    return ERPCredentialsOut(
        erp_type=record.erp_type,
        base_url=record.base_url,
        username_masked=record.username_hint,
        updated_at=record.updated_at,
    )