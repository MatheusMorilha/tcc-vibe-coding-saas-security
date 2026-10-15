# app/routers/emails.py
import logging
import re
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any

import aiosmtplib
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from jinja2 import StrictUndefined, TemplateError, meta
from jinja2.sandbox import SandboxedEnvironment
from pydantic import BaseModel, EmailStr, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import Boolean, DateTime, Integer, String, Text, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Já existentes no projeto (ajuste os imports):
from app.auth import AuthContext, get_auth_context      # user_id, tenant_id, plan
from app.db import async_session_factory, get_session

logger = logging.getLogger("transactional_email")
router = APIRouter(prefix="/v1/emails", tags=["emails"])


# --------------------------------------------------------------------------- #
# Configuração
# --------------------------------------------------------------------------- #
class SMTPSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SMTP_", env_file=".env")

    host: str
    port: int = 587
    username: str
    password: str
    from_address: str            # remetente fixo da plataforma (SPF/DKIM)
    from_name: str = "Plataforma"
    timeout: int = 15


smtp_settings = SMTPSettings()


# --------------------------------------------------------------------------- #
# Modelos (mova para o módulo de models do projeto)
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class EmailTemplate(Base):
    __tablename__ = "email_templates"

    id: Mapped[int] = mapped_column(primary_key=True)
    # NULL = template global da plataforma; preenchido = template da empresa
    tenant_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    slug: Mapped[str] = mapped_column(String(64), index=True)
    subject: Mapped[str] = mapped_column(String(255))
    body_html: Mapped[str] = mapped_column(Text)
    body_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class EmailLog(Base):
    __tablename__ = "email_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(Integer, index=True)
    user_id: Mapped[int] = mapped_column(Integer)
    template_slug: Mapped[str] = mapped_column(String(64))
    recipient: Mapped[str] = mapped_column(String(320))
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|sent|failed
    error: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
_VAR_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class SendEmailRequest(BaseModel):
    template: str = Field(pattern=r"^[a-z0-9_-]{1,64}$")
    to: EmailStr
    variables: dict[str, Any] = Field(default_factory=dict)

    @field_validator("variables")
    @classmethod
    def validate_variables(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(v) > 50:
            raise ValueError("máximo de 50 variáveis")
        for key, val in v.items():
            if not _VAR_NAME.match(key):
                raise ValueError(f"nome de variável inválido: {key!r}")
            if val is not None and not isinstance(val, (str, int, float, bool)):
                raise ValueError(f"variável {key!r} deve ser um valor escalar")
            if isinstance(val, str) and len(val) > 5000:
                raise ValueError(f"variável {key!r} excede 5000 caracteres")
        return v


class SendEmailResponse(BaseModel):
    id: int
    status: str


# --------------------------------------------------------------------------- #
# Renderização segura (sandbox: o template não executa código arbitrário)
# --------------------------------------------------------------------------- #
_html_env = SandboxedEnvironment(autoescape=True, undefined=StrictUndefined)
_text_env = SandboxedEnvironment(autoescape=False, undefined=StrictUndefined)


def _render(tpl: EmailTemplate, variables: dict[str, Any]) -> tuple[str, str, str]:
    try:
        required: set[str] = set()
        for env, src in (
            (_text_env, tpl.subject),
            (_html_env, tpl.body_html),
            (_text_env, tpl.body_text or ""),
        ):
            required |= meta.find_undeclared_variables(env.parse(src))

        missing = sorted(required - variables.keys())
        if missing:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"message": "Variáveis obrigatórias ausentes", "missing": missing},
            )

        subject = _text_env.from_string(tpl.subject).render(**variables)
        subject = re.sub(r"[\r\n]+", " ", subject).strip()  # evita header injection
        html = _html_env.from_string(tpl.body_html).render(**variables)
        text = (
            _text_env.from_string(tpl.body_text).render(**variables)
            if tpl.body_text
            else ""
        )
        return subject, html, text
    except TemplateError as exc:
        logger.error("Falha ao renderizar template %s: %s", tpl.slug, exc)
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "Template inválido ou variáveis incompatíveis"
        )


# --------------------------------------------------------------------------- #
# Envio em background
# --------------------------------------------------------------------------- #
async def _deliver(log_id: int, to: str, subject: str, html: str, text: str) -> None:
    msg = EmailMessage()
    msg["From"] = f"{smtp_settings.from_name} <{smtp_settings.from_address}>"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(text or "Este e-mail requer um cliente com suporte a HTML.")
    msg.add_alternative(html, subtype="html")

    error: str | None = None
    try:
        await aiosmtplib.send(
            msg,
            hostname=smtp_settings.host,
            port=smtp_settings.port,
            username=smtp_settings.username,
            password=smtp_settings.password,
            start_tls=True,
            timeout=smtp_settings.timeout,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Falha no envio do e-mail log_id=%s", log_id)
        error = type(exc).__name__

    async with async_session_factory() as session:
        log = await session.get(EmailLog, log_id)
        if log:
            log.status = "failed" if error else "sent"
            log.error = error
            await session.commit()


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #
@router.post(
    "/send",
    response_model=SendEmailResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def send_transactional_email(
    payload: SendEmailRequest,
    background: BackgroundTasks,
    ctx: AuthContext = Depends(get_auth_context),
    session: AsyncSession = Depends(get_session),
) -> SendEmailResponse:
    # 1. Plano: recurso habilitado?
    if not ctx.plan.transactional_email_enabled:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Seu plano não inclui envio de e-mails transacionais"
        )

    # 2. Plano: cota mensal da empresa
    month_start = datetime.now(timezone.utc).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    used = await session.scalar(
        select(func.count(EmailLog.id)).where(
            EmailLog.tenant_id == ctx.tenant_id,
            EmailLog.created_at >= month_start,
            EmailLog.status != "failed",
        )
    )
    if (used or 0) >= ctx.plan.monthly_email_limit:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Cota mensal de e-mails esgotada")

    # 3. Template: da empresa primeiro; senão, o global. Sempre filtrado por tenant.
    tpl = None
    for tenant_filter in (EmailTemplate.tenant_id == ctx.tenant_id, EmailTemplate.tenant_id.is_(None)):
        tpl = await session.scalar(
            select(EmailTemplate).where(
                EmailTemplate.slug == payload.template,
                EmailTemplate.active.is_(True),
                tenant_filter,
            )
        )
        if tpl:
            break
    if not tpl:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template não encontrado")

    # 4. Renderiza (erros de variáveis retornam 422 ao cliente)
    subject, html, text = _render(tpl, payload.variables)

    # 5. Registra e agenda o envio
    log = EmailLog(
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        template_slug=tpl.slug,
        recipient=payload.to,
    )
    session.add(log)
    await session.commit()
    await session.refresh(log)

    background.add_task(_deliver, log.id, payload.to, subject, html, text)
    return SendEmailResponse(id=log.id, status="pending")