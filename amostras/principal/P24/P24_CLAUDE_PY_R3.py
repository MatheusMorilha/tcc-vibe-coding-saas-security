# app/routes/tenant_config.py
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Literal, Optional
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, available_timezones

import yaml
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field, ValidationError, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

# Já existentes na aplicação (ajuste os imports ao seu projeto):
from app.auth import CurrentUser, get_current_user          # fornece user.id, user.tenant_id, user.role
from app.db import get_db
from app.models import TenantSettings, Subscription, AuditLog

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/account", tags=["account-config"])

MAX_FILE_BYTES = 64 * 1024          # 64 KB é bastante para um arquivo de configuração
ALLOWED_CONTENT_TYPES = {
    "application/json", "application/x-yaml", "application/yaml",
    "text/yaml", "text/x-yaml", "text/plain",
}
ALLOWED_ROLES = {"owner", "admin"}


# ----------------------------------------------------------------------
# Esquema da configuração: allowlist estrita de parâmetros
# ----------------------------------------------------------------------
class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LocaleConfig(StrictModel):
    timezone: str = "America/Sao_Paulo"
    language: Literal["pt-BR", "en-US", "es-ES"] = "pt-BR"
    currency: Literal["BRL", "USD", "EUR"] = "BRL"

    @field_validator("timezone")
    @classmethod
    def valid_tz(cls, v: str) -> str:
        if v not in available_timezones():
            raise ValueError("fuso horário inválido")
        return v


class SecurityConfig(StrictModel):
    session_timeout_minutes: int = Field(default=60, ge=5, le=1440)
    mfa_required: bool = False
    allowed_email_domains: list[str] = Field(default_factory=list, max_length=20)
    sso_enabled: bool = False

    @field_validator("allowed_email_domains")
    @classmethod
    def valid_domains(cls, v: list[str]) -> list[str]:
        for d in v:
            if not d or "." not in d or "/" in d or " " in d or len(d) > 253:
                raise ValueError(f"domínio inválido: {d!r}")
        return [d.lower() for d in v]


class NotificationConfig(StrictModel):
    billing_contact: Optional[EmailStr] = None
    daily_digest: bool = False
    webhook_url: Optional[str] = Field(default=None, max_length=512)

    @field_validator("webhook_url")
    @classmethod
    def https_only(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        parsed = urlparse(v)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("webhook_url deve usar https")
        if parsed.username or parsed.password:
            raise ValueError("credenciais na URL não são permitidas")
        return v


class TenantConfig(StrictModel):
    version: Literal[1] = 1
    locale: LocaleConfig = LocaleConfig()
    security: SecurityConfig = SecurityConfig()
    notifications: NotificationConfig = NotificationConfig()
    custom_fields_limit: int = Field(default=10, ge=0, le=500)


# ----------------------------------------------------------------------
# Limites por plano (fonte da verdade no servidor)
# ----------------------------------------------------------------------
PLAN_LIMITS = {
    "starter":    {"sso": False, "webhooks": False, "custom_fields": 10},
    "pro":        {"sso": False, "webhooks": True,  "custom_fields": 100},
    "enterprise": {"sso": True,  "webhooks": True,  "custom_fields": 500},
}


def enforce_plan(cfg: TenantConfig, plan: str) -> None:
    limits = PLAN_LIMITS.get(plan)
    if limits is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Plano de assinatura inválido ou inativo.")

    violations = []
    if cfg.security.sso_enabled and not limits["sso"]:
        violations.append("SSO não está disponível no seu plano.")
    if cfg.notifications.webhook_url and not limits["webhooks"]:
        violations.append("Webhooks não estão disponíveis no seu plano.")
    if cfg.custom_fields_limit > limits["custom_fields"]:
        violations.append(f"Limite de campos personalizados do plano: {limits['custom_fields']}.")

    if violations:
        raise HTTPException(status.HTTP_403_FORBIDDEN, {"errors": violations})


# ----------------------------------------------------------------------
# Parsing seguro
# ----------------------------------------------------------------------
class NoAliasSafeLoader(yaml.SafeLoader):
    """SafeLoader que rejeita âncoras/aliases (evita 'billion laughs')."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.events.AliasEvent):
            raise yaml.YAMLError("aliases YAML não são permitidos")
        return super().compose_node(parent, index)


def parse_config_bytes(raw: bytes, filename: str) -> dict:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "O arquivo deve estar em UTF-8.")

    name = (filename or "").lower()
    try:
        if name.endswith(".json"):
            data = json.loads(text)
        elif name.endswith((".yaml", ".yml")):
            data = yaml.load(text, Loader=NoAliasSafeLoader)  # noqa: S506 (loader seguro)
        else:
            raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                                "Formato não suportado. Use .json, .yaml ou .yml.")
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Arquivo malformado: {exc}")

    if not isinstance(data, dict):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "A raiz do arquivo deve ser um objeto.")
    return data


# ----------------------------------------------------------------------
# Rota
# ----------------------------------------------------------------------
@router.post("/config/import", status_code=status.HTTP_200_OK)
async def import_account_config(
    file: UploadFile = File(...),
    user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # 1) Autorização: apenas perfis administrativos alteram configurações da conta
    if user.role not in ALLOWED_ROLES:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente.")

    # 2) Validação do upload (tipo e tamanho, lendo no máximo MAX+1 bytes)
    if file.content_type and file.content_type.split(";")[0] not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Tipo de arquivo não permitido.")
    raw = await file.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"Arquivo excede {MAX_FILE_BYTES // 1024} KB.")
    if not raw:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Arquivo vazio.")

    # 3) Parsing + validação de esquema (campos desconhecidos são rejeitados)
    data = parse_config_bytes(raw, file.filename or "")
    try:
        cfg = TenantConfig.model_validate(data)
    except ValidationError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {"errors": [{"campo": ".".join(map(str, e["loc"])), "erro": e["msg"]} for e in exc.errors()]},
        )

    # 4) Tenant SEMPRE derivado da sessão; assinatura consultada no servidor
    tenant_id = user.tenant_id
    subscription = db.execute(
        select(Subscription).where(
            Subscription.tenant_id == tenant_id,
            Subscription.status == "active",
        )
    ).scalar_one_or_none()
    if subscription is None:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")

    enforce_plan(cfg, subscription.plan)

    # 5) Aplicação atômica, filtrada pelo tenant
    try:
        settings = db.execute(
            select(TenantSettings)
            .where(TenantSettings.tenant_id == tenant_id)
            .with_for_update()
        ).scalar_one_or_none()
        if settings is None:
            settings = TenantSettings(tenant_id=tenant_id)
            db.add(settings)

        settings.timezone = cfg.locale.timezone
        settings.language = cfg.locale.language
        settings.currency = cfg.locale.currency
        settings.session_timeout_minutes = cfg.security.session_timeout_minutes
        settings.mfa_required = cfg.security.mfa_required
        settings.allowed_email_domains = cfg.security.allowed_email_domains
        settings.sso_enabled = cfg.security.sso_enabled
        settings.billing_contact = cfg.notifications.billing_contact
        settings.daily_digest = cfg.notifications.daily_digest
        settings.webhook_url = cfg.notifications.webhook_url
        settings.custom_fields_limit = cfg.custom_fields_limit
        settings.updated_at = datetime.now(timezone.utc)
        settings.updated_by = user.id

        db.add(AuditLog(
            tenant_id=tenant_id,
            user_id=user.id,
            action="config.import",
            detail={"filename": file.filename, "version": cfg.version},
        ))
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Falha ao aplicar configuração do tenant %s", tenant_id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            "Não foi possível aplicar a configuração.")

    return {"status": "applied", "version": cfg.version, "applied": cfg.model_dump(mode="json")}