from datetime import datetime
from enum import Enum

from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import DateTime, Enumas SQLEnum, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


# ============================================================
# Configuração
# ============================================================

DATABASE_URL= "sqlite:///./app.db"

engine= create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread":False},
)

SessionLocal= sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


app= FastAPI()


# ============================================================
# Modelos
# ============================================================

class ExpenseStatus(str, Enum):
    PENDING= "pending"
    APPROVED= "approved"
    REJECTED= "rejected"


class User(Base):
    __tablename__= "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)


class ExpenseRequest(Base):
    __tablename__= "expense_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    status: Mapped[ExpenseStatus] = mapped_column(
        SQLEnum(ExpenseStatus),
        default=ExpenseStatus.PENDING,
        nullable=False,
    )
    approved_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
    )
    approved_at: Mapped[datetime| None] = mapped_column(
        DateTime,
        nullable=True,
    )


Base.metadata.create_all(engine)


# ============================================================
# Dependências
# ============================================================

def get_db():
    db= SessionLocal()

    try:
        yield db
    finally:
        db.close()


class CurrentUser:
    def __init__(self, id: int, tenant_id: int):
        self.id= id
        self.tenant_id= tenant_id


def get_current_user()-> CurrentUser:
    """
    Em produção, o tenant_id e o user_id devem vir de uma
    identidade autenticada (JWT/session), nunca do payload da requisição.
    """
    return CurrentUser(
        id=1,
        tenant_id=10,
    )


# ============================================================
# Schemas
# ============================================================

class ApprovalResponse(BaseModel):
    expense_request_id: int
    status: ExpenseStatus
    approved_by: int
    approved_at: datetime


# ============================================================
# Rota
# ============================================================

@app.post(
    "/expense-requests/{expense_request_id}/approve",
    response_model=ApprovalResponse,
    status_code=status.HTTP_200_OK,
)
def approve_expense_request(
    expense_request_id: int,
    db: Session= Depends(get_db),
    current_user: CurrentUser= Depends(get_current_user),
):
    # O tenant_id faz parte da consulta.
    # Portanto, uma solicitação pertencente a outro tenant
    # não pode ser acessada apenas informando seu ID.
    expense_request= (
        db.query(ExpenseRequest)
        .filter(
            ExpenseRequest.id== expense_request_id,
            ExpenseRequest.tenant_id== current_user.tenant_id,
        )
        .with_for_update()
        .first()
    )

    if expense_requestis None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Solicitação de despesa não encontrada.",
        )

    # Evita aprovar novamente uma solicitação já processada.
    if expense_request.status!= ExpenseStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"A solicitação já foi processada "
                f"com status '{expense_request.status.value}'."
            ),
        )

    # Registra a aprovação.
    now= datetime.utcnow()

    expense_request.status= ExpenseStatus.APPROVED
    expense_request.approved_by= current_user.id
    expense_request.approved_at= now

    db.commit()
    db.refresh(expense_request)

    return ApprovalResponse(
        expense_request_id=expense_request.id,
        status=expense_request.status,
        approved_by=expense_request.approved_by,
        approved_at=expense_request.approved_at,
    )