import os
import smtplib
from email.message import EmailMessage
from pathlib import Path

from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader, select_autoescape

load_dotenv()

SMTP_HOST = os.environ["SMTP_HOST"]
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER = os.environ["SMTP_USER"]
SMTP_PASSWORD = os.environ["SMTP_PASSWORD"]
EMAIL_FROM = os.environ["EMAIL_FROM"]

TEMPLATE_DIR = Path(__file__).parent / "templates"

template_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)


def send_transactional_email(
    recipient: str,
    template_name: str,
    variables: dict,
) -> None:
    template = template_env.get_template(template_name)
    html_content = template.render(**variables)

    message = EmailMessage()
    message["Subject"] = variables.get(
        "subject", "Notificação"
    )
    message["From"] = EMAIL_FROM
    message["To"] = recipient

    message.set_content(
        "Esta mensagem contém uma versão HTML."
    )
    message.add_alternative(html_content, subtype="html")

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        timeout=15,
    ) as smtp:
        smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(message)

from typing import Any, Literal

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from pydantic import BaseModel, EmailStr, Field

from app.email_service import send_transactional_email

app = FastAPI(title="SaaS Email API")


class AuthenticatedUser(BaseModel):
    user_id: str
    tenant_id: str


def get_current_user() -> AuthenticatedUser:
    """
    Substituir pela validação real do token
    e pela resolução do tenant autenticado.
    """
    raise HTTPException(
        status_code=401,
        detail="Autenticação não configurada.",
    )


class EmailRequest(BaseModel):
    recipient: EmailStr
    template: Literal["welcome.html"]
    variables: dict[str, Any] = Field(
        default_factory=dict,
        max_length=20,
    )


@app.post("/api/v1/emails", status_code=202)
def send_email(
    payload: EmailRequest,
    background_tasks: BackgroundTasks,
    user: AuthenticatedUser = Depends(get_current_user),
):
    # O tenant vem da identidade autenticada,
    # nunca de um tenant_id enviado pelo cliente.
    if not user.tenant_id:
        raise HTTPException(
            status_code=403,
            detail="Tenant não autorizado.",
        )

    required_variables = {
        "nome",
        "empresa",
        "mensagem",
    }

    if not required_variables.issubset(
        payload.variables.keys()
    ):
        raise HTTPException(
            status_code=422,
            detail="Variáveis obrigatórias ausentes.",
        )

    # Impede que o cliente sobrescreva o assunto
    # por meio de variáveis arbitrárias.
    allowed_variables = {
        "nome",
        "empresa",
        "mensagem",
    }

    if set(payload.variables) != allowed_variables:
        raise HTTPException(
            status_code=422,
            detail="Variáveis inválidas para o template.",
        )

    background_tasks.add_task(
        send_transactional_email,
        str(payload.recipient),
        payload.template,
        payload.variables,
    )

    return {
        "message": "Solicitação de envio aceita.",
        "tenant_id": user.tenant_id,
    }