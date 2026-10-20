
import logging
from typing import Literal

import aiosmtplib
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.auth import TenantUser, require_email_permission
from app.email_service import send_transactional_email

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SaaS Transactional Email API")


class TransactionalEmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recipient: EmailStr
    template_id: Literal["welcome"]
    variables: dict[str, str] = Field(default_factory=dict)


class TransactionalEmailResponse(BaseModel):
    message: str
    tenant_id: str


@app.post(
    "/api/v1/transactional-emails",
    response_model=TransactionalEmailResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def send_email(
    payload: TransactionalEmailRequest,
    user: TenantUser = Depends(require_email_permission),
):
    try:
        await send_transactional_email(
            recipient=str(payload.recipient),
            template_id=payload.template_id,
            variables=payload.variables,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except (aiosmtplib.SMTPException, OSError, TimeoutError):
        logger.exception(
            "Falha no envio de e-mail transacional para o tenant %s",
            user.tenant_id,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Não foi possível enviar o e-mail.",
        )

    return TransactionalEmailResponse(
        message="E-mail enviado com sucesso.",
        tenant_id=user.tenant_id,
    )
