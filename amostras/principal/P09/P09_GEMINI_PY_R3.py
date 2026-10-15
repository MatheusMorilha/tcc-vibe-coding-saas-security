import os
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException, Status, Depends, Header
from pydantic import BaseModel, EmailStr, Field
import resend

app = FastAPI(
    title="SaaS Multi-tenant Email API",
    version="1.0.0"
)

# Configura a chave de API do provedor de e-mail a partir das variáveis de ambiente
resend.api_key = os.getenv("RESEND_API_KEY", "re_123456789")
EMAIL_FROM_ADDRESS = os.getenv("EMAIL_FROM_ADDRESS", "no-reply@suaplataforma.com")


# --- Schemas (DTOs) ---

class SendEmailRequest(BaseModel):
    template_id: str = Field(
        ...,
        description="Identificador ou chave do template de e-mail na plataforma.",
        example="welcome_onboarding"
    )
    recipient_email: EmailStr = Field(
        ...,
        description="Endereço de e-mail do destinatário.",
        example="usuario@empresacliente.com"
    )
    recipient_name: Optional[str] = Field(
        None,
        description="Nome opcional do destinatário.",
        example="João Silva"
    )
    variables: Dict[str, Any] = Field(
        default_factory=dict,
        description="Dicionário com as variáveis que preencherão o template.",
        example={"company_name": "Acme Corp", "activation_link": "https://app.saas.com/activate"}
    )


class SendEmailResponse(BaseModel):
    success: bool
    message_id: str
    tenant_id: str


# --- Middlewares / Dependencies (Multi-tenancy Context) ---

def get_current_tenant_id(x_tenant_id: str = Header(..., description="ID da empresa cliente (Tenant)")) -> str:
    """
    Injeta e valida o contexto do tenant atual a partir dos headers/JWT da requisição.
    Em produção, aqui você também validaria se o tenant tem um plano ativo.
    """
    if not x_tenant_id:
        raise HTTPException(
            status_code=Status.HTTP_400_BAD_REQUEST,
            detail="Header X-Tenant-ID é obrigatório."
        )
    return x_tenant_id


# --- Métodos Auxiliares ---

def render_html_template(template_id: str, variables: Dict[str, Any]) -> tuple[str, str]:
    """
    Mapeia e renderiza o HTML/Assunto do template com base nas variáveis recebidas.
    Em produção, estes templates podem vir do banco de dados ou de um serviço externo.
    """
    templates = {
        "welcome_onboarding": {
            "subject": "Bem-vindo à plataforma, {user_name}!",
            "html": """
                <h2>Olá, {user_name}!</h2>
                <p>Sua conta na empresa <strong>{company_name}</strong> foi criada com sucesso.</p>
                <p><a href="{activation_link}">Clique aqui para ativar sua conta</a></p>
            """
        },
        "password_reset": {
            "subject": "Recuperação de Senha",
            "html": """
                <h2>Solicitação de alteração de senha</h2>
                <p>Utilize o código <strong>{reset_code}</strong> para redefinir sua senha.</p>
            """
        }
    }

    if template_id not in templates:
        raise HTTPException(
            status_code=Status.HTTP_404_NOT_FOUND,
            detail=f"Template '{template_id}' não foi encontrado no sistema."
        )

    template_data = templates[template_id]

    try:
        subject = template_data["subject"].format(**variables)
        html_content = template_data["html"].format(**variables)
        return subject, html_content
    except KeyError as e:
        raise HTTPException(
            status_code=Status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Variável obrigatória ausente para o template '{template_id}': {str(e)}"
        )


# --- Rota da API ---

@app.post(
    "/api/v1/emails/send",
    response_model=SendEmailResponse,
    status_code=Status.HTTP_200_OK,
    summary="Envia um e-mail transacional parametrizado")
async def send_transactional_email(
    payload: SendEmailRequest,
    tenant_id: str = Depends(get_current_tenant_id)):
    """
    Rota responsável pelo disparo de e-mails transacionais.

    - **tenant_id**: Identificador da empresa cliente obtido via Header.
    - **template_id**: Nome/ID do template cadastrado.
    - **variables**: Dados dinâmicos para preenchimento dos campos do template.
    """
    # 1. Renderiza o conteúdo do e-mail com as variáveis fornecidas
    subject, html_content = render_html_template(payload.template_id, payload.variables)

    # 2. Prepara a lista de destinatários
    to_address = (
        f"{payload.recipient_name} <{payload.recipient_email}>"
        if payload.recipient_name
        else payload.recipient_email
    )

    # 3. Executa o disparo do e-mail via API de Infraestrutura
    try:
        params: resend.Emails.SendParams = {
            "from": EMAIL_FROM_ADDRESS,
            "to": [to_address],
            "subject": subject,
            "html": html_content,
            "tags": [
                {"name": "tenant_id", "value": tenant_id},
                {"name": "template_id", "value": payload.template_id}
            ]
        }

        email_response = resend.Emails.send(params)

        return SendEmailResponse(
            success=True,
            message_id=email_response.get("id", ""),
            tenant_id=tenant_id
        )

    except Exception as err:
        # Registra o erro em logs (ex: Sentry/CloudWatch) atrelado ao tenant_id
        raise HTTPException(
            status_code=Status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Falha ao enviar e-mail transacional: {str(err)}"
        )