import os
import smtplib
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, status
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from pydantic import BaseModel, EmailStr, Field


app= FastAPI(title="SaaS Transactional Email API")

TEMPLATE_DIR= Path("templates")

jinja= Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    undefined=StrictUndefined,
    autoescape=True,
)


class AuthContext(BaseModel):
    tenant_id: str
    user_id: str


class TransactionalEmailRequest(BaseModel):
    recipient: EmailStr
    template: str = Field(min_length=1, max_length=100)
    variables: dict[str, Any] = Field(default_factory=dict)


def get_auth_context()-> AuthContext:
    # Em produção, substituir por JWT/OAuth2/API Key.
    # O tenant_id deve vir exclusivamente das credenciais autenticadas.
    return AuthContext(
        tenant_id="tenant-example",
        user_id="user-example",
    )


def send_email(
    recipient: str,
    subject: str,
    html: str,
    text: str,
)-> None:
    message= EmailMessage()
    message["From"] = os.environ["EMAIL_FROM"]
    message["To"] = recipient
    message["Subject"] = subject

    message.set_content(text)
    message.add_alternative(html, subtype="html")

    with smtplib.SMTP(
        os.environ["SMTP_HOST"],
        int(os.environ.get("SMTP_PORT","587")),
    ) as smtp:
        smtp.starttls()
        smtp.login(
            os.environ["SMTP_USERNAME"],
            os.environ["SMTP_PASSWORD"],
        )
        smtp.send_message(message)


@app.post(
    "/api/v1/emails/transactional",
    status_code=status.HTTP_202_ACCEPTED,
)
def send_transactional_email(
    request: TransactionalEmailRequest,
    auth: AuthContext= Depends(get_auth_context),
):
    """
    Envia um e-mail transacional usando um template parametrizado.

    O tenant é obtido do contexto de autenticação, não da requisição.
    """

    # Evita path traversal e restringe o template a nomes simples.
    if (
        "/" in request.template
        or "\\" in request.template
        or ".." in request.template
    ):
        raise HTTPException(
            status_code=400,
            detail="Nome de template inválido.",
        )

    try:
        html_template= jinja.get_template(
            f"{request.template}.html"
        )
        text_template= jinja.get_template(
            f"{request.template}.txt"
        )
    except Exception:
        raise HTTPException(
            status_code=404,
            detail="Template não encontrado.",
        )

    # O tenant autenticado pode ser utilizado para selecionar
    # configurações/templates específicos desse locatário.
    variables= {
        **request.variables,
        "tenant_id": auth.tenant_id,
    }

    try:
        html= html_template.render(**variables)
        text= text_template.render(**variables)
    except Exception:
        raise HTTPException(
            status_code=422,
            detail="Variáveis obrigatórias do template não fornecidas.",
        )

    subject= variables.get("subject")

    if not subject:
        raise HTTPException(
            status_code=422,
            detail="A variável 'subject' é obrigatória.",
        )

    try:
        send_email(
            recipient=str(request.recipient),
            subject=subject,
            html=html,
            text=text,
        )
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Não foi possível enviar o e-mail.",
        )

    return {
        "status": "accepted",
        "tenant_id": auth.tenant_id,
        "recipient": str(request.recipient),
        "template": request.template,
    }