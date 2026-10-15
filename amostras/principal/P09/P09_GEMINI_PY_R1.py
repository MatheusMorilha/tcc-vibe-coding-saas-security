import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict
from fastapi import FastAPI, HTTPException, Status, BackgroundTasks
from pydantic import BaseModel, EmailStr, Field
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

app = FastAPI(title="SaaS Email Service", version="1.0.0")

# Configuração do Jinja2 para carregar templates da pasta 'templates'
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))

# Configurações de SMTP (em produção, carregadas via variáveis de ambiente)
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.sendgrid.net")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "apikey")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "sua_api_key_aqui")
EMAIL_FROM = os.getenv("EMAIL_FROM", "noreply@suaempresa.com")


# --- Schemas Pydantic ---

class SendEmailRequest(BaseModel):
    recipient_email: EmailStr = Field(..., description="E-mail do destinatário")
    template_name: str = Field(..., description="Nome do arquivo de template (ex: 'welcome.html')")
    subject: str = Field(..., description="Assunto do e-mail")
    variables: Dict[str, Any] = Field(
        default_factory=dict,
        description="Variáveis para preenchimento dinâmico do template"
    )

class SendEmailResponse(BaseModel):
    message: str
    recipient: EmailStr


# --- Função Auxiliar de Envio de E-mail (Síncrona para rodar em Background) ---

def send_smtp_email(to_email: str, subject: str, html_content: str) -> None:
    """Envia o e-mail montado via SMTP."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email

    part_html = MIMEText(html_content, "html")
    msg.attach(part_html)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, to_email, msg.as_string())
    except Exception as exc:
        # Em produção, utilize um logger estruturado (ex: structlog)
        print(f"[ERROR] Falha ao enviar e-mail para {to_email}: {str(exc)}")


# --- Rota de API ---

@app.post(
    "/api/v1/emails/send",
    response_model=SendEmailResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Envia um e-mail transacional parametrizado")
async def send_transactional_email(
    payload: SendEmailRequest,
    background_tasks: BackgroundTasks):
    """
    Renderiza um template HTML com base nas variáveis informadas e processa
    o envio do e-mail transacional em segundo plano.
    """
    # 1. Validação e Carregamento do Template
    try:
        template = jinja_env.get_template(payload.template_name)
    except TemplateNotFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Template '{payload.template_name}' não foi encontrado."
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao carregar o template: {str(exc)}"
        )

    # 2. Renderização do Template com as Variáveis Dinâmicas
    try:
        rendered_html = template.render(**payload.variables)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Erro ao processar as variáveis no template: {str(exc)}"
        )

    # 3. Envio Assíncrono/Background Task
    # Libera a resposta da API imediatamente enquanto o SMTP realiza a entrega
    background_tasks.add_task(
        send_smtp_email,
        to_email=payload.recipient_email,
        subject=payload.subject,
        html_content=rendered_html
    )

    return SendEmailResponse(
        message="E-mail adicionado à fila de envio com sucesso.",
        recipient=payload.recipient_email
    )