import logging
import os
import re
import uuid
from email.message import EmailMessage
from typing import Any, Optional

import aiosmtplib
import jwt
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jinja2 import StrictUndefined, TemplateError
from jinja2.sandbox import SandboxedEnvironment
from pydantic import BaseModel, EmailStr, Field, field_validator

logger = logging.getLogger("transactional_email")
router = APIRouter(prefix="/api/v1/emails", tags=["emails"])
bearer = HTTPBearer(auto_error=True)

# --------------------------------------------------------------------------
# Configuração (via variáveis de ambiente; nunca versionar segredos)
# --------------------------------------------------------------------------
JWT_PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "RS256")
SMTP_HOST = os.environ["SMTP_HOST"]
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.environ["SMTP_USER"]
SMTP_PASSWORD = os.environ["SMTP_PASSWORD"]
MAIL_FROM = os.environ["MAIL_FROM"]

MAX_VARIABLES = 50
MAX_VALUE_LENGTH = 5_000

# Sandbox: impede acesso a atributos/funções perigosas nos templates
_jinja = SandboxedEnvironment(autoescape=True, undefined=StrictUndefined)


# --------------------------------------------------------------------------
# Contexto autenticado
# --------------------------------------------------------------------------
class CurrentUser(BaseModel):
    user_id: str
    tenant_id: str


async def get_current_user(
    cred: HTTPAuthorizationCredentials = Depends(bearer),
) -> CurrentUser:
    try:
        payload = jwt.decode(
            cred.credentials, JWT_PUBLIC_KEY, algorithms=[JWT_ALGORITHM]
        )
        return CurrentUser(user_id=payload["sub"], tenant_id=payload["tenant_id"])
    except (jwt.PyJWTError, KeyError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido.")


# --------------------------------------------------------------------------
# Camada de dados (substitua pelas suas implementações reais)
# --------------------------------------------------------------------------
class EmailTemplate(BaseModel):
    key: str
    subject: str
    body_html: str
    body_text: Optional[str] = None


async def fetch_template(tenant_id: str, template_key: str) -> Optional[EmailTemplate]:
    """
    SELECT ... FROM email_templates
    WHERE key = :key AND (tenant_id = :tenant_id OR tenant_id IS NULL)
    O filtro por tenant_id é obrigatório (templates próprios + globais do sistema).
    """
    raise NotImplementedError


async def has_active_subscription(tenant_id: str) -> bool:
    raise NotImplementedError


async def consume_email_quota(tenant_id: str) -> bool:
    """Incremento atômico (ex.: UPDATE ... WHERE usado < limite) da cota do plano."""
    raise NotImplementedError


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------
class SendEmailRequest(BaseModel):
    template_key: str = Field(..., pattern=r"^[a-z0-9_\-]{1,64}$")
    to: EmailStr
    variables: dict[str, Any] = Field(default_factory=dict)

    @field_validator("variables")
    @classmethod
    def validate_variables(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(v) > MAX_VARIABLES:
            raise ValueError(f"Máximo de {MAX_VARIABLES} variáveis.")
        for name, value in v.items():
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name):
                raise ValueError(f"Nome de variável inválido: {name!r}")
            # Apenas tipos simples: evita objetos aninhados arbitrários
            if not isinstance(value, (str, int, float, bool, type(None))):
                raise ValueError(f"Tipo não suportado na variável {name!r}.")
            if isinstance(value, str) and len(value) > MAX_VALUE_LENGTH:
                raise ValueError(f"Variável {name!r} excede o tamanho máximo.")
        return v


class SendEmailResponse(BaseModel):
    message_id: str
    status: str = "queued"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _render(template: EmailTemplate, variables: dict[str, Any]) -> tuple[str, str, str]:
    try:
        subject = _jinja.from_string(template.subject).render(**variables)
        html = _jinja.from_string(template.body_html).render(**variables)
        text = (
            _jinja.from_string(template.body_text).render(**variables)
            if template.body_text
            else ""
        )
    except TemplateError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Falha ao renderizar o template: {exc}",
        )
    # Previne header injection: remove quebras de linha do assunto
    subject = re.sub(r"[\r\n]+", " ", subject).strip()[:200]
    return subject, html, text


async def _deliver(message_id: str, tenant_id: str, to: str, subject: str,
                   html: str, text: str) -> None:
    msg = EmailMessage()
    msg["From"] = MAIL_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg["Message-ID"] = f"<{message_id}@{MAIL_FROM.split('@')[-1]}>"
    msg.set_content(text or "Este e-mail requer um cliente com suporte a HTML.")
    msg.add_alternative(html, subtype="html")

    try:
        await aiosmtplib.send(
            msg,
            hostname=SMTP_HOST,
            port=SMTP_PORT,
            username=SMTP_USER,
            password=SMTP_PASSWORD,
            start_tls=True,
            timeout=15,
        )
        logger.info("email_sent message_id=%s tenant=%s", message_id, tenant_id)
    except Exception:
        # Não registrar destinatário/conteúdo (dados pessoais)
        logger.exception("email_failed message_id=%s tenant=%s", message_id, tenant_id)
        # Ponto de extensão: enfileirar retry / marcar falha no banco


# --------------------------------------------------------------------------
# Rota
# --------------------------------------------------------------------------
@router.post(
    "/send",
    response_model=SendEmailResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def send_transactional_email(
    payload: SendEmailRequest,
    background_tasks: BackgroundTasks,
    user: CurrentUser = Depends(get_current_user),
) -> SendEmailResponse:
    # 1. Assinatura ativa
    if not await has_active_subscription(user.tenant_id):
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")

    # 2. Template restrito ao tenant (ou global do sistema)
    template = await fetch_template(user.tenant_id, payload.template_key)
    if template is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template não encontrado.")

    # 3. Renderiza antes de consumir cota (erros de template não gastam cota)
    subject, html, text = _render(template, payload.variables)

    # 4. Cota do plano
    if not await consume_email_quota(user.tenant_id):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Cota de e-mails do plano excedida."
        )

    # 5. Envio assíncrono
    message_id = uuid.uuid4().hex
    background_tasks.add_task(
        _deliver, message_id, user.tenant_id, payload.to, subject, html, text
    )
    return SendEmailResponse(message_id=message_id)