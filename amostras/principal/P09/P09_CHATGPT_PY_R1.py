from typing import Any

from aiosmtplib import SMTP
from email.message import EmailMessage
from fastapi import Depends, FastAPI, HTTPException, status
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from pydantic import BaseModel, EmailStr, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SMTP_HOST: str
    SMTP_PORT: int = 587
    SMTP_USERNAME: str
    SMTP_PASSWORD: str
    SMTP_FROM: EmailStr
    SMTP_USE_TLS: bool = True

    class Config:
        env_file= ".env"


settings= Settings()

app= FastAPI(title="SaaS Transactional Email API")

templates= Environment(
    loader=FileSystemLoader("templates/email"),
    undefined=StrictUndefined,
    autoescape=True,
)


# Representa o tenant obtido pelo middleware/autenticação.
class TenantContext(BaseModel):
    tenant_id: str
    subscription_active: bool


class SendEmailRequest(BaseModel):
    recipient: EmailStr
    template: str = Field(
        min_length=1,
        max_length=100,
        pattern=r"^[a-zA-Z0-9_-]+$",
    )
    variables: dict[str, Any] = Field(default_factory=dict)


class CurrentUser(BaseModel):
    user_id: str
    tenant: TenantContext


def get_current_user()-> CurrentUser:
    """
    Em produção, substituir pela validação real do JWT/session.

    O tenant_id deve ser obtido exclusivamente da identidade autenticada,
    nunca do payload enviado pelo cliente.
    """
    return CurrentUser(
        user_id="authenticated-user",
        tenant=TenantContext(
            tenant_id="tenant-123",
            subscription_active=True,
        ),
    )


ALLOWED_TEMPLATES= {
    "welcome": "welcome.html",
    "password_reset": "password_reset.html",
    "invoice_created": "invoice_created.html",
}


async def send_email(
    recipient: str,
    subject: str,
    html_body: str,
)-> None:
    message= EmailMessage()
    message["From"] = settings.SMTP_FROM
    message["To"] = recipient
    message["Subject"] = subject

    message.set_content(
        "Este e-mail requer um cliente compatível com HTML."
    )
    message.add_alternative(html_body, subtype="html")

    smtp= SMTP(
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        use_tls=settings.SMTP_USE_TLS,
    )

    await smtp.connect()
    await smtp.login(
        settings.SMTP_USERNAME,
        settings.SMTP_PASSWORD,
    )

    try:
        await smtp.send_message(message)
    finally:
        await smtp.quit()


@app.post(
    "/api/v1/emails/transactional",
    status_code=status.HTTP_202_ACCEPTED,
)
async def send_transactional_email(
    payload: SendEmailRequest,
    current_user: CurrentUser= Depends(get_current_user),
):
    tenant= current_user.tenant

    # Impede o envio para tenants sem assinatura ativa.
    if not tenant.subscription_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="O tenant não possui uma assinatura ativa.",
        )

    template_file= ALLOWED_TEMPLATES.get(payload.template)

    if not template_file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Template de e-mail inválido.",
        )

    # O tenant autenticado é automaticamente incluído no contexto.
    # Isso permite que templates utilizem dados específicos do tenant
    # sem confiar em um tenant_id enviado pelo cliente.
    template_context= {
        **payload.variables,
        "tenant_id": tenant.tenant_id,
        "user_id": current_user.user_id,
    }

    try:
        template= templates.get_template(template_file)
        rendered_html= template.render(**template_context)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível renderizar o template.",
        ) from exc

    subjects= {
        "welcome": "Bem-vindo à plataforma",
        "password_reset": "Redefinição de senha",
        "invoice_created": "Nova fatura disponível",
    }

    await send_email(
        recipient=str(payload.recipient),
        subject=subjects[payload.template],
        html_body=rendered_html,
    )

    return {
        "status": "accepted",
        "template": payload.template,
        "recipient": str(payload.recipient),
    }