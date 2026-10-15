import secrets
import string
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from redis.asyncio import Redis

# --- Schemas (Pydantic) ---

class ResendVerificationRequest(BaseModel):
    email: EmailStr
    tenant_id: str

class APIResponse(BaseModel):
    message: str
    success: bool


# --- Interfaces & Mocks de Infraestrutura ---

async def get_db_session() -> AsyncSession:
    """Injeta a sessão assíncrona do SQLAlchemy (Configurar de acordo com a sua app)."""
    pass

async def get_redis_client() -> Redis:
    """Injeta o cliente assíncrono do Redis."""
    pass

async def send_verification_code_event(recipient: str, code: str, tenant_id: str):
    """
    Simulação do disparo de e-mail ou SMS.
    Idealmente integrado a uma fila (ex: Celery, BullMQ, AWS SQS) ou serviço de e-mail (SendGrid, SES).
    """
    print(f"[MAILER] Disparando código {code} para {recipient} (Tenant: {tenant_id})")


# --- Service Core ---

class VerificationCodeService:
    def __init__(self, db: AsyncSession, redis: Redis):
        self.db = db
        self.redis = redis

    @staticmethod
    def generate_secure_code(length: int = 6) -> str:
        """Gera um código numérico aleatório criptograficamente seguro."""
        digits = string.digits
        return ''.join(secrets.choice(digits) for _ in range(length))

    async def resend_code(
        self,
        email: str,
        tenant_id: str,
        background_tasks: BackgroundTasks):
        # 1. Consulta o usuário garantindo isolamento multilocatário (Tenant Isolation)
        # Assumindo uma Model `User` com colunas email, tenant_id e is_verified
        query = select(User).where(
            User.email == email,
            User.tenant_id == tenant_id
        )
        result = await self.db.execute(query)
        user = result.scalars().first()

        # Evita Enumeração de Usuários: Se o usuário não existir, responde sucesso sem disparar nada.
        if not user:
            return {"message": "Se o contato existir, um novo código será enviado.", "success": True}

        # 2. Verifica se o contato já foi verificado
        if user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Este contato já foi verificado."
            )

        # 3. Rate Limiting por Redis (Bloqueia reenvios frequentes, ex: 1 por minuto)
        cooldown_key = f"auth:resend_cooldown:{tenant_id}:{user.id}"
        is_on_cooldown = await self.redis.get(cooldown_key)

        if is_on_cooldown:
            ttl = await self.redis.ttl(cooldown_key)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Aguarde {ttl} segundos antes de solicitar um novo código."
            )

        # 4. Geração do Novo Código e Salvamento
        code = self.generate_secure_code(length=6)

        # Armazena o código no Redis com TTL de 10 minutos (600 segundos)
        code_key = f"auth:verification_code:{tenant_id}:{user.id}"

        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.set(code_key, code, ex=600)  # Expira em 10 min
            pipe.set(cooldown_key, "1", ex=60)  # Cooldown de 60 seg entre envios
            await pipe.execute()

        # 5. Disparo Assíncrono do Envio (Não bloqueia a resposta HTTP)
        background_tasks.add_task(
            send_verification_code_event,
            recipient=user.email,
            code=code,
            tenant_id=tenant_id
        )

        return {"message": "Se o contato existir, um novo código será enviado.", "success": True}


# --- Router FastAPI ---

router = APIRouter(prefix="/v1/auth", tags=["Autenticação"])

@router.post(
    "/resend-verification",
    response_model=APIResponse,
    status_code=status.HTTP_200_OK,
    summary="Reenvia o código de verificação para o usuário")
async def resend_verification_code(
    payload: ResendVerificationRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
    redis: Redis = Depends(get_redis_client)):
    """
    Rota responsável por reenviar o código de confirmação.

    - **Isolamento SaaS:** Requer `tenant_id` e `email`.
    - **Segurança:** Implementa Cooldown de 60s via Redis para conter abusos.
    - **Privacidade:** Retorna uma mensagem genérica para mitigar User Enumeration Attacks.
    """
    service = VerificationCodeService(db=db, redis=redis)
    return await service.resend_code(
        email=payload.email,
        tenant_id=payload.tenant_id,
        background_tasks=background_tasks
    )