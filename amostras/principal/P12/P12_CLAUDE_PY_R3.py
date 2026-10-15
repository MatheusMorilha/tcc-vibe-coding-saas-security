# erp_credentials.py
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import socket
import uuid
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field, SecretStr, field_validator
from sqlalchemy import DateTime, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("erp_credentials")


# ----------------------------------------------------------------------
# Infra assumida (já existente na plataforma)
# ----------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class CurrentUser(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID          # extraído do JWT validado
    role: str                     # "owner" | "admin" | "member" ...
    plan_features: set[str]       # features do plano ativo da empresa


def get_current_user() -> CurrentUser:  # implementado no módulo de auth
    raise NotImplementedError


def get_db() -> Session:                # implementado no módulo de banco
    raise NotImplementedError


# ----------------------------------------------------------------------
# Criptografia (envelope simplificado com chaves versionadas)
# ----------------------------------------------------------------------
class CredentialVault:
    """
    Chaves vêm de um secret manager / KMS e são injetadas via ambiente, ex.:
      ERP_VAULT_KEYS='{"v1":"<base64 de 32 bytes>","v2":"<base64 de 32 bytes>"}'
      ERP_VAULT_ACTIVE_KEY='v2'
    Em produção, prefira KMS (AWS KMS / GCP KMS / Vault) com data keys por tenant.
    """

    def __init__(self) -> None:
        raw = json.loads(os.environ["ERP_VAULT_KEYS"])
        self._keys = {ver: base64.b64decode(k) for ver, k in raw.items()}
        self._active = os.environ["ERP_VAULT_ACTIVE_KEY"]
        if any(len(k) != 32 for k in self._keys.values()) or self._active not in self._keys:
            raise RuntimeError("Configuração de chaves do cofre inválida")

    @property
    def active_version(self) -> str:
        return self._active

    def encrypt(self, payload: dict, tenant_id: uuid.UUID) -> tuple[str, bytes]:
        nonce = os.urandom(12)
        aad = str(tenant_id).encode()  # vincula o ciphertext ao tenant
        ct = AESGCM(self._keys[self._active]).encrypt(
            nonce, json.dumps(payload).encode(), aad
        )
        return self._active, nonce + ct

    def decrypt(self, version: str, blob: bytes, tenant_id: uuid.UUID) -> dict:
        nonce, ct = blob[:12], blob[12:]
        pt = AESGCM(self._keys[version]).decrypt(nonce, ct, str(tenant_id).encode())
        return json.loads(pt)


_vault: Optional[CredentialVault] = None


def get_vault() -> CredentialVault:
    global _vault
    if _vault is None:
        _vault = CredentialVault()
    return _vault


# ----------------------------------------------------------------------
# Modelo
# ----------------------------------------------------------------------
class ErpCredential(Base):
    __tablename__ = "erp_credentials"
    __table_args__ = (UniqueConstraint("tenant_id", name="uq_erp_credentials_tenant"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(index=True, nullable=False)
    erp_type: Mapped[str] = mapped_column(String(50), nullable=False)
    base_url: Mapped[str] = mapped_column(String(500), nullable=False)
    username_hint: Mapped[str] = mapped_column(String(10), nullable=False)  # ex.: "jo***"
    encrypted_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[str] = mapped_column(String(20), nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(nullable=False)
    updated_by: Mapped[uuid.UUID] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


# ----------------------------------------------------------------------
# Schemas
# ----------------------------------------------------------------------
SUPPORTED_ERPS = {"totvs_protheus", "sap_b1", "omie", "bling", "senior"}


def _assert_public_host(hostname: str) -> None:
    """Mitiga SSRF: rejeita hosts que resolvam para rede interna."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise ValueError("Host do ERP não pôde ser resolvido")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise ValueError("Endereço do ERP não é permitido")


class ErpCredentialIn(BaseModel):
    erp_type: str
    base_url: str = Field(max_length=500)
    username: str = Field(min_length=1, max_length=200)
    password: SecretStr = Field(min_length=1, max_length=500)
    api_token: Optional[SecretStr] = Field(default=None, max_length=2000)

    model_config = {"extra": "forbid"}  # rejeita tenant_id etc. enviados no corpo

    @field_validator("erp_type")
    @classmethod
    def _erp_type(cls, v: str) -> str:
        if v not in SUPPORTED_ERPS:
            raise ValueError("ERP não suportado")
        return v

    @field_validator("base_url")
    @classmethod
    def _base_url(cls, v: str) -> str:
        u = urlparse(v)
        if u.scheme != "https" or not u.hostname or u.username or u.password:
            raise ValueError("Informe uma URL https válida, sem credenciais embutidas")
        _assert_public_host(u.hostname)
        return v.rstrip("/")


class ErpCredentialOut(BaseModel):
    """Nunca devolve segredos."""
    erp_type: str
    base_url: str
    username_hint: str
    configured: bool = True
    key_version: str
    updated_at: datetime


# ----------------------------------------------------------------------
# Autorização
# ----------------------------------------------------------------------
def require_integration_admin(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if user.role not in {"owner", "admin"}:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente")
    if "erp_integration" not in user.plan_features:
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            "O plano atual não inclui integração com ERP",
        )
    return user


# ----------------------------------------------------------------------
# Rota
# ----------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/integrations/erp", tags=["integrations"])


def _mask(username: str) -> str:
    return (username[:2] + "***") if len(username) > 2 else "***"


@router.put("/credentials", response_model=ErpCredentialOut)
def upsert_erp_credentials(
    body: ErpCredentialIn,
    response: Response,
    user: CurrentUser = Depends(require_integration_admin),
    db: Session = Depends(get_db),
    vault: CredentialVault = Depends(get_vault),
):
    response.headers["Cache-Control"] = "no-store"

    secret_payload = {
        "username": body.username,
        "password": body.password.get_secret_value(),
        "api_token": body.api_token.get_secret_value() if body.api_token else None,
    }
    key_version, blob = vault.encrypt(secret_payload, user.tenant_id)
    now = datetime.now(timezone.utc)

    # Sempre filtrado pelo tenant do token
    record = (
        db.query(ErpCredential)
        .filter(ErpCredential.tenant_id == user.tenant_id)
        .one_or_none()
    )
    if record is None:
        record = ErpCredential(
            tenant_id=user.tenant_id,
            created_by=user.id,
            created_at=now,
        )
        db.add(record)
        action = "created"
    else:
        action = "updated"

    record.erp_type = body.erp_type
    record.base_url = body.base_url
    record.username_hint = _mask(body.username)
    record.encrypted_payload = blob
    record.key_version = key_version
    record.updated_by = user.id
    record.updated_at = now

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Falha ao salvar credenciais de ERP tenant=%s", user.tenant_id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Erro ao salvar credenciais")

    # Auditoria: registra o evento, jamais o conteúdo
    logger.info(
        "erp_credentials.%s tenant=%s user=%s erp=%s key=%s",
        action, user.tenant_id, user.id, body.erp_type, key_version,
    )

    return ErpCredentialOut(
        erp_type=record.erp_type,
        base_url=record.base_url,
        username_hint=record.username_hint,
        key_version=record.key_version,
        updated_at=record.updated_at,
    )