from pathlib import Path
import os
import smtplib
from email.message import EmailMessage

from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from jinja2 import Environment, FileSystemLoader, TemplateNotFound


app= FastAPI(title="SaaS Transactional Email API")

TEMPLATES_DIR= Path("templates")

jinja= Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=True,
)


class AuthContext(BaseModel):
    tenant_id: str
    user_id: str


class SendEmailRequest(BaseModel):
    recipient: EmailStr
    template: str = Field(min_length=1, max_length=100)
    variables: dict[str, str] = Field(default_factory=dict)


def get_auth_context()-> AuthContext:
    """
    Em produção, esta função deve validar o JWT/session e obter
    tenant_id e user_id exclusivamente das credenciais autenticadas.
    """
    return AuthContext(
        tenant_id="tenant-from-auth-token",
        user_id="user-from-auth-token",
    )


def send_email(
    recipient: str,
    subject: str,
    html_body: str,
)-> None:
    message= EmailMessage()
    message["From"] = os.environ["SMTP_FROM"]
    message["To"] = recipient
    message["Subject"] = subject

    message.set_content("Este e-mail requer um cliente compatível com HTML.")
    message.add_alternative(html_body, subtype="html")

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
    request: SendEmailRequest,
    auth: AuthContext= Depends(get_auth_context),
):
    """
    Envia um e-mail transacional utilizando um template parametrizado.

    O tenant é obtido da autenticação, nunca do payload.
    """

    # Exemplo de validação adicional:
    # verificar no banco se o tenant possui assinatura ativa.
    #
    # subscription = get_subscription(auth.tenant_id)
    # if not subscription.active:
    #     raise HTTPException(
    #         status_code=403,
    #         detail="Assinatura inativa",
    #     )

    # Impede path traversal: somente nomes simples de templates.
    if "/" in request.templateor "\\" in request.template:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nome de template inválido.",
        )

    try:
        template= jinja.get_template(f"{request.template}.html")
    except TemplateNotFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template não encontrado.",
        )

    try:
        rendered= template.render(**request.variables)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Variáveis incompatíveis com o template.",
        )

    # O assunto também pode ser armazenado junto à configuração
    # do template no banco de dados.
    subject= f"Notificação da sua empresa"

    try:
        send_email(
            recipient=str(request.recipient),
            subject=subject,
            html_body=rendered,
        )
    except (smtplib.SMTPException, OSError):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Não foi possível enviar o e-mail.",
        )

    return {
        "status": "accepted",
        "tenant_id": auth.tenant_id,
        "recipient": request.recipient,
        "template": request.template,
    }