from enum import Enum
from typing import Optional
from fastapi import FastAPI, Depends, Query, HTTPException, status
from sqlalchemy import Column, Integer, String, Float, ForeignKey, create_engine, select, asc, desc
from sqlalchemy.orm import declarative_base, Session, sessionmaker

# ------------------------------------------------------------------------------
# Configuração / Mapeamento do Banco de Dados
# ------------------------------------------------------------------------------
Base = declarative_base()

class Contract(Base):
    __tablename__ = "contracts"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, nullable=False, index=True)  # Chave de isolamento multitenant
    title = Column(String, nullable=False)
    client_name = Column(String, nullable=False)
    value = Column(Float, nullable=False)
    status = Column(String, nullable=False)

# Enum para validação estrita da direção de ordenação via FastAPI/Pydantic
class SortOrder(str, Enum):
    ASC = "asc"
    DESC = "desc"

# Mapeamento explícito das colunas permitidas para ordenação (Evita SQL Injection)
ALLOWED_SORT_COLUMNS = {
    "id": Contract.id,
    "title": Contract.title,
    "client_name": Contract.client_name,
    "value": Contract.value,
    "status": Contract.status,
}

# Enum derivado para validação automática do parâmetro `sort_by` no Swagger/OpenAPI
SortColumnEnum = Enum("SortColumnEnum", {k: k for k in ALLOWED_SORT_COLUMNS.keys()}, type=str)

# ------------------------------------------------------------------------------
# Autenticação & Contexto Multitenant
# ------------------------------------------------------------------------------
class CurrentUser:
    """Representa o usuário autenticado extraído do token JWT."""
    def __init__(self, user_id: int, tenant_id: int):
        self.user_id = user_id
        self.tenant_id = tenant_id

def get_current_user() -> CurrentUser:
    """
    Mock do middleware/dependency de autenticação JWT.
    Em produção, este método decodifica o token JWT enviado no Header Authorization
    e injeta o tenant_id associado ao usuário logado.
    """
    return CurrentUser(user_id=42, tenant_id=1001)

# Dependência de Banco de Dados
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------------------------------------------------------------------
# Rota da API
# ------------------------------------------------------------------------------
app = FastAPI(title="SaaS Multi-tenant Contracts API")

@app.get("/api/v1/contracts", status_code=status.HTTP_200_OK)
def list_contracts(
    sort_by: Optional[SortColumnEnum] = Query(
        default=SortColumnEnum.id,
        description="Coluna para ordenação dos contratos"),
    order: SortOrder = Query(
        default=SortOrder.ASC,
        description="Direção da ordenação: 'asc' para ascendente ou 'desc' para descendente"),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user)):
    """
    Lista os contratos da empresa (tenant) associada ao usuário autenticado,
    permitindo escolha dinâmica da coluna e direção de ordenação.
    """
    # 1. Recupera o atributo ORM correspondente à coluna validada
    column_attr = ALLOWED_SORT_COLUMNS.get(sort_by.value)

    if column_attr is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Coluna de ordenação inválida."
        )

    # 2. Define a direção da ordenação
    sort_clause = desc(column_attr) if order == SortOrder.DESC else asc(column_attr)

    # 3. Monta a consulta garantindo estritamente o isolamento de Tenant
    query = (
        select(Contract)
        .where(Contract.tenant_id == current_user.tenant_id)
        .order_by(sort_clause)
    )

    contracts = db.scalars(query).all()

    return {
        "tenant_id": current_user.tenant_id,
        "count": len(contracts),
        "data": [
            {
                "id": c.id,
                "title": c.title,
                "client_name": c.client_name,
                "value": c.value,
                "status": c.status
            }
            for c in contracts
        ]
    }