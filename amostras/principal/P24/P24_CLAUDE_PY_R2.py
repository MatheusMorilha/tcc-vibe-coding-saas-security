"""
Rota: POST /api/v1/account/settings/import

Dependências: fastapi, python-multipart, pydantic>=2, email-validator,
              pyyaml, sqlalchemy>=2
"""
import hashlib
import ipaddress
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Optional
from urllib.parse import urlparse
from zoneinfo import available_timezones

import yaml
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    ValidationError,
    field_validator,
)
from sqlalchemy import JSON, DateTime, ForeignKey, String, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("settings_import")

# ----------------------------------------------------------------------
# Modelos de persistência (simplificados)
# ----------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(primary_key=True)
    plan: Mapped[str] = mapped_column(String(32))  # basic | pro | enterprise
    status: Mapped[str] = mapped_column(String(16))  # active | suspended


class TenantSettings(Base):
    __tablename__ = "tenant_settings"
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), primary_key=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_by: Mapped[Optional[int]]
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(index=True)
    user_id: Mapped[int]
    action: Mapped[str] = mapped_column(String(64))
    details: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# ----------------------------------------------------------------------
# Autenticação / sessão (a implementar conforme a infraestrutura)
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class CurrentUser:
    id: int
    tenant_id: int  # SEMPRE vem do token/sessão, nunca do arquivo enviado
    role: str  # "owner" | "admin" | "member"


def get_current_user() -> CurrentUser:  # pragma: no cover
    raise NotImplementedError("Injetar a dependência real de autenticação")


def get_db() -> Session:  # pragma: no cover
    raise NotImplementedError("Injetar a dependência real de sessão do banco")


# ----------------------------------------------------------------------
# Schema do arquivo de configuração (lista de permissões estrita)
# Campos como tenant_id, plan, roles e billing NÃO existem aqui, então
# `extra="forbid"` faz o arquivo ser rejeitado se tentar enviá-los.
# ----------------------------------------------------------------------

MAX_FILE_BYTES = 256 * 1024
ALLOWED_EXTENSIONS = (".json", ".yaml", ".yml")
TIMEZONES = available_timezones()

# Recursos condicionados ao plano contratado
PLAN_FEATURES: dict[str, set[str]] = {
    "basic": set(),
    "pro": {"webhook"},
    "enterprise": {"webhook", "ip_allowlist"},
}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class NotificationSettings(StrictModel):
    billing_emails: list[EmailStr] = Field(max_length=5)
    weekly_digest: bool = False


class SecuritySettings(StrictModel):
    session_timeout_minutes: int = Field(ge=5, le=1440)
    require_mfa: bool = False
    allowed_ip_ranges: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("allowed_ip_ranges")
    @classmethod
    def validate_ranges(cls, v: list[str]) -> list[str]:
        for item in v:
            ipaddress.ip_network(item, strict=True)  # ValueError -> 422
        return v


class BrandingSettings(StrictModel):
    display_name: str = Field(min_length=1, max_length=100)
    primary_color: str = Field(pattern=r"^#[0-9a-fA-F]{6}$")

    @field_validator("display_name")
    @classmethod
    def no_markup_or_control_chars(cls, v: str) -> str:
        if re.search(r"[<>\x00-\x1f\x7f]", v):
            raise ValueError("caracteres não permitidos")
        return v


class WebhookSettings(StrictModel):
    url: str = Field(max_length=2048)
    events: list[Literal["invoice.created", "invoice.paid", "user.created"]] = Field(
        min_length=1, max_length=10
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("a URL deve usar https")
        host = parsed.hostname.lower()
        if host == "localhost" or host.endswith((".local", ".internal")):
            raise ValueError("host não permitido")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return v  # nome DNS; revalidar o IP resolvido no momento do envio (SSRF)
        if not ip.is_global:
            raise ValueError("endereço IP não permitido")
        return v


class TenantConfig(StrictModel):
    schema_version: Literal[1]
    locale: Optional[Literal["pt-BR", "en-US", "es-ES"]] = None
    timezone: Optional[str] = None
    currency: Optional[Literal["BRL", "USD", "EUR"]] = None
    notifications: Optional[NotificationSettings] = None
    security: Optional[SecuritySettings] = None
    branding: Optional[BrandingSettings] = None
    webhook: Optional[WebhookSettings] = None

    @field_validator("timezone")
    @classmethod
    def validate_tz(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in TIMEZONES:
            raise ValueError("timezone inválido")
        return v


# ----------------------------------------------------------------------
# Leitura e parsing seguros
# ----------------------------------------------------------------------


async def read_limited(file: UploadFile, limit: int) -> bytes:
    """Lê o upload em blocos e aborta ao passar do limite (evita estourar memória)."""
    chunks, total = [], 0
    while chunk := await file.read(64 * 1024):
        total += len(chunk)
        if total > limit:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Arquivo muito grande")
        chunks.append(chunk)
    return b"".join(chunks)


def parse_document(raw: bytes, filename: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "O arquivo deve estar em UTF-8")

    try:
        if filename.endswith(".json"):
            doc = json.loads(text)
        else:
            # Rejeita aliases/âncoras YAML (ataque "billion laughs").
            # Somente safe_load: nunca yaml.load / pickle (execução de código).
            if any(isinstance(e, yaml.AliasEvent) for e in yaml.parse(text)):
                raise ValueError("aliases YAML não são permitidos")
            doc = yaml.safe_load(text)
    except (ValueError, yaml.YAMLError, RecursionError):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Arquivo malformado")

    if not isinstance(doc, dict):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "A raiz deve ser um objeto")
    return doc


# ----------------------------------------------------------------------
# Regras de negócio
# ----------------------------------------------------------------------


def enforce_plan(plan: str, cfg: TenantConfig) -> None:
    allowed = PLAN_FEATURES.get(plan, set())
    required = set()
    if cfg.webhook is not None:
        required.add("webhook")
    if cfg.security is not None and cfg.security.allowed_ip_ranges:
        required.add("ip_allowlist")
    missing = required - allowed
    if missing:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"Recursos não incluídos no plano atual: {', '.join(sorted(missing))}",
        )


def deep_merge(base: dict, patch: dict) -> dict:
    out = dict(base)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def changed_paths(old: dict, new: dict, prefix: str = "") -> list[str]:
    paths = []
    for k in sorted(set(old) | set(new)):
        a, b = old.get(k), new.get(k)
        if a == b:
            continue
        if isinstance(a, dict) and isinstance(b, dict):
            paths += changed_paths(a, b, f"{prefix}{k}.")
        else:
            paths.append(f"{prefix}{k}")
    return paths


# ----------------------------------------------------------------------
# Rota
# ----------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/account/settings", tags=["settings"])


@router.post("/import")
async def import_settings(
    file: UploadFile = File(...),
    dry_run: bool = Query(False, description="Valida e mostra o diff sem gravar"),
    user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # 1. Autorização: só administradores alteram configurações da conta
    if user.role not in {"owner", "admin"}:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente")

    # 2. Validação do upload
    filename = (file.filename or "").lower()
    if not filename.endswith(ALLOWED_EXTENSIONS):
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Use .json, .yaml ou .yml")
    raw = await read_limited(file, MAX_FILE_BYTES)

    # 3. Parsing seguro + validação estrita contra o schema
    doc = parse_document(raw, filename)
    try:
        cfg = TenantConfig.model_validate(doc)
    except ValidationError as exc:
        # Devolve apenas campo e mensagem, sem ecoar os valores enviados
        errors = [{"campo": ".".join(map(str, e["loc"])), "erro": e["msg"]} for e in exc.errors()]
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=errors)

    patch = cfg.model_dump(mode="json", exclude_unset=True, exclude_none=True)
    patch.pop("schema_version", None)
    if not patch:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Nenhum parâmetro informado")

    # 4. Tenant vem exclusivamente da identidade autenticada
    tenant = db.scalar(select(Tenant).where(Tenant.id == user.tenant_id))
    if tenant is None or tenant.status != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Conta inativa")

    # 5. Limites do plano (lido do banco, não do arquivo)
    enforce_plan(tenant.plan, cfg)

    # 6. Aplicação atômica, com lock da linha da própria empresa
    now = datetime.now(timezone.utc)
    try:
        current = db.scalar(
            select(TenantSettings)
            .where(TenantSettings.tenant_id == user.tenant_id)
            .with_for_update()
        )
        if current is None:
            current = TenantSettings(tenant_id=user.tenant_id, data={})
            db.add(current)

        before = current.data or {}
        after = deep_merge(before, patch)
        changes = changed_paths(before, after)

        if not dry_run and changes:
            current.data = after
            current.updated_by = user.id
            current.updated_at = now
            db.add(
                AuditLog(
                    tenant_id=user.tenant_id,
                    user_id=user.id,
                    action="settings.import",
                    details={
                        "file_sha256": hashlib.sha256(raw).hexdigest(),
                        "changed": changes,  # só os caminhos, sem valores
                    },
                    created_at=now,
                )
            )
        if dry_run:
            db.rollback()
        else:
            db.commit()
    except Exception:
        db.rollback()
        logger.exception("Falha ao aplicar configuração tenant=%s", user.tenant_id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Não foi possível aplicar a configuração")

    return {
        "applied": not dry_run and bool(changes),
        "dry_run": dry_run,
        "changed_fields": changes,
    }