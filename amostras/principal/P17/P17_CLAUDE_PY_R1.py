"""
POST /api/v1/expense-requests/{request_id}/approve

Aprova uma solicitação de despesa de forma segura em um ambiente multilocatário.

Garantias:
  * O tenant (company_id) vem SEMPRE da identidade autenticada, nunca do cliente.
  * Toda consulta/atualização é filtrada por company_id (isolamento entre empresas).
  * Recursos de outras empresas respondem 404 (não revela que existem).
  * Exige permissão explícita, assinatura ativa e respeita o limite de alçada.
  * Bloqueia autoaprovação (segregação de funções).
  * Transição de estado atômica (PENDING -> APPROVED) em um único UPDATE condicional,
    evitando condição de corrida / aprovação dupla.
  * Trilha de auditoria gravada na mesma transação.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    DateTime, ForeignKey, Numeric, String, Text, select, update,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #


class Base(DeclarativeBase):
    pass


class ExpenseStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"


class ExpenseRequest(Base):
    __tablename__ = "expense_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    company_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("companies.id"), index=True, nullable=False
    )
    requester_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    amount: Mapped[Decimal] = mapped_column(Numeric(14, 2), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    approved_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True))
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    approval_comment: Mapped[Optional[str]] = mapped_column(Text)


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    company_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("companies.id"), index=True, nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # ACTIVE, PAST_DUE...
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    company_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    actor_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    action: Mapped[str] = mapped_column(String(64))
    entity: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# --------------------------------------------------------------------------- #
# Dependências (implementadas em outro módulo da aplicação)
# --------------------------------------------------------------------------- #


class AuthUser(BaseModel):
    """Identidade extraída de um token JWT já validado (assinatura/expiração)."""

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    company_id: uuid.UUID               # tenant: fonte de verdade para isolamento
    permissions: frozenset[str]
    approval_limit: Optional[Decimal]   # None = sem limite de alçada


def get_current_user() -> AuthUser:  # pragma: no cover - substituído via DI real
    raise NotImplementedError


def get_db() -> Session:  # pragma: no cover - substituído via DI real
    raise NotImplementedError


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #


class ApproveExpenseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")  # rejeita campos inesperados
    comment: Optional[str] = Field(default=None, max_length=1000)


class ApproveExpenseOut(BaseModel):
    request_id: uuid.UUID
    status: ExpenseStatus
    approved_by: uuid.UUID
    approved_at: datetime
    message: str = "Solicitação de despesa aprovada com sucesso."


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #

router = APIRouter(prefix="/api/v1/expense-requests", tags=["expense-requests"])

APPROVE_PERMISSION = "expense:approve"


def _require_active_subscription(db: Session, company_id: uuid.UUID) -> None:
    now = datetime.now(timezone.utc)
    sub = db.execute(
        select(Subscription.id).where(
            Subscription.company_id == company_id,
            Subscription.status == "ACTIVE",
            (Subscription.expires_at.is_(None)) | (Subscription.expires_at > now),
        )
    ).first()
    if sub is None:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="A assinatura da empresa não está ativa.",
        )


@router.post(
    "/{request_id}/approve",
    response_model=ApproveExpenseOut,
    status_code=status.HTTP_200_OK,
)
def approve_expense_request(
    request_id: uuid.UUID,  # UUID não sequencial: dificulta enumeração
    payload: ApproveExpenseIn,
    user: AuthUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ApproveExpenseOut:
    # 1) Autorização por permissão (RBAC)
    if APPROVE_PERMISSION not in user.permissions:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Sem permissão para aprovar despesas.")

    # 2) Plano de assinatura ativo para o tenant do usuário
    _require_active_subscription(db, user.company_id)

    now = datetime.now(timezone.utc)

    try:
        # 3) Transição atômica: só atualiza se TODAS as condições forem verdadeiras.
        #    Isso elimina a janela de corrida entre "verificar" e "atualizar".
        conditions = [
            ExpenseRequest.id == request_id,
            ExpenseRequest.company_id == user.company_id,           # isolamento de tenant
            ExpenseRequest.status == ExpenseStatus.PENDING.value,   # máquina de estados
            ExpenseRequest.requester_id != user.id,                 # sem autoaprovação
        ]
        if user.approval_limit is not None:
            conditions.append(ExpenseRequest.amount <= user.approval_limit)  # alçada

        updated = db.execute(
            update(ExpenseRequest)
            .where(*conditions)
            .values(
                status=ExpenseStatus.APPROVED.value,
                approved_by=user.id,
                approved_at=now,
                approval_comment=payload.comment,
            )
            .returning(ExpenseRequest.id)
        ).first()

        if updated is None:
            # Nenhuma linha afetada: descobre o motivo (sempre filtrando por tenant).
            db.rollback()
            _raise_failure_reason(db, request_id, user)

        # 4) Auditoria na MESMA transação
        db.add(
            AuditLog(
                id=uuid.uuid4(),
                company_id=user.company_id,
                actor_id=user.id,
                action="expense_request.approved",
                entity="expense_request",
                entity_id=request_id,
                created_at=now,
            )
        )
        db.commit()
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise  # o handler global converte em 500 genérico, sem vazar detalhes internos

    return ApproveExpenseOut(
        request_id=request_id,
        status=ExpenseStatus.APPROVED,
        approved_by=user.id,
        approved_at=now,
    )


def _raise_failure_reason(db: Session, request_id: uuid.UUID, user: AuthUser) -> None:
    """Traduz a falha do UPDATE condicional em um erro HTTP adequado."""
    row = db.execute(
        select(
            ExpenseRequest.status,
            ExpenseRequest.requester_id,
            ExpenseRequest.amount,
        ).where(
            ExpenseRequest.id == request_id,
            ExpenseRequest.company_id == user.company_id,  # nunca consultar fora do tenant
        )
    ).first()

    # Inexistente OU pertencente a outra empresa: mesma resposta (sem vazamento).
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Solicitação não encontrada.")

    if row.status != ExpenseStatus.PENDING.value:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"A solicitação não pode ser aprovada: situação atual é {row.status}.",
        )
    if row.requester_id == user.id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Não é permitido aprovar a própria solicitação.",
        )
    if user.approval_limit is not None and row.amount > user.approval_limit:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "O valor da solicitação excede o seu limite de aprovação.",
        )

    # Estado mudou entre o UPDATE e o SELECT (concorrência)
    raise HTTPException(status.HTTP_409_CONFLICT, "A solicitação foi alterada. Tente novamente.")