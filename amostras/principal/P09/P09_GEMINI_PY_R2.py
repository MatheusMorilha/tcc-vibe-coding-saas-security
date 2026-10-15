import os
from typing import Any, Dict
from fastapi import FastAPI, HTTPException, status, Depends
from pydantic import BaseModel, EmailStr
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

app = FastAPI(title="SaaS Transactional Mailer API")

# Configuração do Jinja2 para carregar templates da pasta 'templates'
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=True
)

# Esquema de validação dos dados de entrada
class SendEmailRequest(BaseModel):
    recipient_email: EmailStr
    template_name: str
    subject: str
    variables: Dict[str, Any]

    model_config = {
        "json_schema_extra": {
            "example": {
                "recipient_email": "usuario@empresa.com.br",
                "template_name": "boas_vindas.html",
                "subject": "Bem-vindo à plataforma!",
                "variables": {
                    "nome_usuario": "Carlos Eduardo",
                    "nome_empresa": "Acme Corp",
                    "link_login": "https://app.saas.com/login"
                }
            }
        }
    }


def render_template(template_name: str, variables: Dict[str, Any]) -> str:
    """Carrega o template do disco e injeta as variáveis."""
    try:
        template = jinja_env.get_template(template_name)
        return template.render(**variables)
    except TemplateNotFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Template '{template_name}' não foi encontrado no servidor."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao processar o template: {str(e)}"
        )


def send_email_service(to_email: str, subject: str, html_content: str) -> bool:
    """
    Serviço responsável por integrar com o provedor SMTP ou API de e-mail
    (ex: SendGrid, Amazon SES, Mailgun, Resend).
    """
    # Exemplo mockado de disparo: substitua pelo SDK do seu provedor
    print(f"--- [EMAIL SENT] ---")
    print(f"Para: {to_email}")
    print(f"Assunto: {subject}")
    print(f"Conteúdo HTML:\n{html_content[:150]}...")
    print(f"---------------------")
    return True


@app.post(
    "/api/v1/emails/send",
    status_code=status.HTTP_200_OK,
    summary="Envia um e-mail transacional via template")
async def send_transactional_email(payload: SendEmailRequest):
    # 1. Renderiza o HTML com as variáveis passadas
    html_content = render_template(payload.template_name, payload.variables)

    # 2. Executa o disparo do e-mail
    email_sent = send_email_service(
        to_email=payload.recipient_email,
        subject=payload.subject,
        html_content=html_content
    )

    if not email_sent:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha ao disparar o e-mail pelo provedor."
        )

    return {
        "status": "success",
        "message": f"E-mail enviado com sucesso para {payload.recipient_email}."
    }