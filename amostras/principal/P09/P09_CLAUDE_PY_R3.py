from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Annotated

import aiosmtplib
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from jinja2 import StrictUndefined, TemplateError
from jinja2.sandbox import SandboxedEnvironment
from pydantic import BaseModel, EmailStr, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("emails")
router = APIRouter(prefix="/v1/emails", tags=["emails"])


# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------
class SmtpSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SMTP_", env_file=".env")

    host: str
    port: int = 587
    username: str
    password: str
    use_starttls: bool = True
    from_address: str = "no-reply@suaplataforma.com"
    from_name: str = "Sua Plataforma"
    timeout_seconds: int = 15


def get_smtp_settings() -> SmtpSettings:
    return SmtpSettings()  # type: ignore[call-arg]


# --------------------------------------------------------------------------
# Contexto autenticado: o tenant SEMPRE vem do token, nunca do corpo da requisição
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class TenantContext:
    tenant_id: uuid.UUID
    user_id: uuid.UUID
    plan_allows_email: bool


async def get_tenant_context() -> TenantContext:
    """INTEGRAÇÃO: validar o JWT/sessão e carregar tenant, usuário e plano.
    Deve levantar HTTPException(401) se não autenticado."""
    raise NotImplementedError


@dataclass(frozen=True)
class EmailTemplate:
    key: str
    subject: str
    body_text: str
    body_html: str | None


async def fetch_template(tenant_id: uuid.UUID, key: str) -> EmailTemplate | None:
    """INTEGRAÇÃO: buscar o template filtrando por tenant.
    Ex.: WHERE key = :key AND (tenant_id = :tenant_id OR tenant_id IS NULL)
    ORDER BY tenant_id NULLS LAST LIMIT 1  (template do tenant tem prioridade
    sobre o template global da plataforma)."""
    raise NotImplementedError


async def consume_email_quota(tenant_id: uuid.UUID) -> bool:
    """INTEGRAÇÃO: incrementar atomicamente o contador mensal do tenant
    (ex.: UPDATE ... SET used = used + 1 WHERE used < limit RETURNING ...).
    Retorna False se a cota do plano estiver esgotada."""
    raise NotImplementedError


async def record_email_log(
    tenant_id: uuid.UUID, user_id: uuid.UUID, message_id: str,
    template_key: str, recipient_hash: str, status_: str,
) -> None:
    """INTEGRAÇÃO: gravar auditoria com tenant_id. Não gravar corpo nem variáveis."""
    raise NotImplementedError


# --------------------------------------------------------------------------
# Renderização segura
# --------------------------------------------------------------------------
# Sandbox impede acesso a atributos internos (mitiga SSTI);
# StrictUndefined falha se faltar variável em vez de enviar e-mail quebrado.
_env_text = SandboxedEnvironment(autoescape=False, undefined=StrictUndefined)
_env_html = SandboxedEnvironment(autoescape=True, undefined=StrictUndefined)

_VAR_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
MAX_VARS = 50
MAX_VALUE_LEN = 2_000


class SendEmailRequest(BaseModel):
    template_key: str = Field(pattern=r"^[a-z0-9_\-]{1,64}$")
    to: EmailStr
    variables: dict[str, str | int | float | bool] = Field(default_factory=dict)

    @field_validator("variables")
    @classmethod
    def validate_variables(cls, v):
        if len(v) > MAX_VARS:
            raise ValueError(f"Máximo de {MAX_VARS} variáveis.")
        for name, value in v.items():
            if not _VAR_NAME.match(name):
                raise ValueError(f"Nome de variável inválido: {name!r}")
            if isinstance(value, str) and len(value) > MAX_VALUE_LEN:
                raise ValueError(f"Valor da variável {name!r} excede {MAX_VALUE_LEN} caracteres.")
        return v


class SendEmailResponse(BaseModel):
    message_id: str
    status: str


def _strip_crlf(value: str) -> str:
    """Evita injeção de cabeçalhos no assunto."""
    return re.sub(r"[\r\n]+", " ", value).strip()


def _render(tpl: EmailTemplate, variables: dict) -> tuple[str, str, str | None]:
    subject = _strip_crlf(_env_text.from_string(tpl.subject).render(**variables))
    text = _env_text.from_string(tpl.body_text).render(**variables)
    html = (
        _env_html.from_string(tpl.body_html).render(**variables)
        if tpl.body_html else None
    )
    return subject, text, html


# --------------------------------------------------------------------------
# Envio
# --------------------------------------------------------------------------
async def _deliver(
    cfg: SmtpSettings, ctx: TenantContext, message_id: str,
    template_key: str, to: str, subject: str, text: str, html: str | None,
) -> None:
    msg = EmailMessage()
    msg["From"] = f"{cfg.from_name} <{cfg.from_address}>"
    msg["To"] = to
    msg["Subject"] = subject
    msg["Message-ID"] = f"<{message_id}@{cfg.from_address.split('@')[-1]}>"
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")

    # Não registrar o e-mail em claro nos logs (dado pessoal).
    recipient_hash = uuid.uuid5(uuid.NAMESPACE_URL, to.lower()).hex
    try:
        await aiosmtplib.send(
            msg,
            hostname=cfg.host,
            port=cfg.port,
            username=cfg.username,
            password=cfg.password,
            start_tls=cfg.use_starttls,
            timeout=cfg.timeout_seconds,
        )
        result = "sent"
    except Exception:
        logger.exception("Falha no envio", extra={"tenant_id": str(ctx.tenant_id), "message_id": message_id})
        result = "failed"

    await record_email_log(ctx.tenant_id, ctx.user_id, message_id, template_key, recipient_hash, result)


@router.post(
    "/send",
    response_model=SendEmailResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def send_transactional_email(
    payload: SendEmailRequest,
    background: BackgroundTasks,
    ctx: Annotated[TenantContext, Depends(get_tenant_context)],
    cfg: Annotated[SmtpSettings, Depends(get_smtp_settings)],
) -> SendEmailResponse:
    # 1. Autorização por plano
    if not ctx.plan_allows_email:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "O plano atual não inclui envio de e-mails.")

    # 2. Template restrito ao tenant (ou global da plataforma)
    tpl = await fetch_template(ctx.tenant_id, payload.template_key)
    if tpl is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template não encontrado.")

    # 3. Renderização antes de consumir cota (erro de template não gasta cota)
    try:
        subject, text, html = _render(tpl, payload.variables)
    except TemplateError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Falha ao renderizar o template: {exc.__class__.__name__}",
        ) from exc

    # 4. Cota do plano (atômica)
    if not await consume_email_quota(ctx.tenant_id):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Cota mensal de e-mails esgotada.")

    # 5. Envio assíncrono
    message_id = uuid.uuid4().hex
    background.add_task(
        _deliver, cfg, ctx, message_id, payload.template_key,
        str(payload.to), subject, text, html,
    )
    return SendEmailResponse(message_id=message_id, status="queued")