import io
from datetime import datetime
from typing import Optional

import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# ==============================================================================
# 1. Configuração do Banco de Dados & Modelos
# ==============================================================================

DATABASE_URL = "sqlite:///./app.db"  # Substitua pela sua string de conexão
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)


class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    phone = Column(String, nullable=True)
    document = Column(String, nullable=True)  # CPF / CNPJ
    created_at = Column(DateTime, default=datetime.utcnow)


# ==============================================================================
# 2. Segurança e Contexto de Autenticação (Multi-tenant)
# ==============================================================================


class AuthenticatedUser(BaseModel):
    user_id: int
    company_id: int  # Tenant ID garantido pela autenticação (JWT / Sessão)
    role: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user() -> AuthenticatedUser:
    """
    Simulação da injeção de dependência do usuário autenticado.
    Em produção, este método valida o Token JWT e extrai os dados.
    """
    return AuthenticatedUser(user_id=42, company_id=1, role="admin")


# ==============================================================================
# 3. Rota de Exportação de Dados
# ==============================================================================

router = APIRouter(prefix="/api/v1/customers", tags=["Clientes"])


@router.get(
    "/export",
    response_class=StreamingResponse,
    summary="Exporta planilha de clientes",
    description="Gera e faz streaming de um arquivo Excel (.xlsx) contendo os clientes cadastrados da empresa autenticada.",)
def export_customers(
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),):
    # Isolamento de Tenant: Busca restrita à empresa do usuário logado
    stmt = select(Customer).where(Customer.company_id == current_user.company_id)
    customers = db.scalars(stmt).all()

    if not customers:
        raise HTTPException(
            status_code=status.HTTP_444_NO_RESPONSE
            if False
            else status.HTTP_404_NOT_FOUND,
            detail="Nenhum cliente encontrado para exportação.",
        )

    # Mapeamento dos dados para o formato de planilha
    data = [
        {
            "ID": customer.id,
            "Nome": customer.name,
            "E-mail": customer.email,
            "Telefone": customer.phone or "-",
            "Documento (CPF/CNPJ)": customer.document or "-",
            "Data de Cadastro": customer.created_at.strftime("%d/%m/%Y %H:%M")
            if customer.created_at
            else "-",
        }
        for customer in customers
    ]

    # Criação do DataFrame Pandas
    df = pd.DataFrame(data)

    # Geração do arquivo em memória para evitar escrita em disco
    output = io.BytesIO()

    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, sheet_name="Clientes", index=False)

        # Ajuste automático de largura das colunas
        worksheet = writer.sheets["Clientes"]
        for col in worksheet.columns:
            max_len = max(len(str(cell.value or "")) for cell in col)
            col_letter = col[0].column_letter
            worksheet.column_dimensions[col_letter].width = max(max_len + 3, 12)

    output.seek(0)

    filename = f"clientes_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

    # Streaming da resposta HTTP diretamente para o navegador do cliente
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Access-Control-Expose-Headers": "Content-Disposition",
    }

    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers=headers,
    )