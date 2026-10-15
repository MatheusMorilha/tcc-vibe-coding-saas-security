from io import BytesIO
from typing import Dict, List, Any
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
import pandas as pd

# Supondo a existência dos módulos de infraestrutura da sua aplicação
from app.database import get_db
from app.models import Customer
from app.auth import get_current_tenant_id  # Função que extrai o tenant_id do JWT do usuário

router = APIRouter(prefix="/customers", tags=["Customers"])

# --- SCHEMAS ---

class ImportErrorDetail(BaseModel):
    row: int
    email: str | None
    error: str

class ImportSummaryResponse(BaseModel):
    total_processed: int
    created_count: int
    skipped_count: int
    failed_count: int
    errors: List[ImportErrorDetail]


# --- ROTA DE IMPORTAÇÃO ---

BATCH_SIZE = 500  # Tamanho do lote para gravação em massa

@router.post(
    "/import",
    response_model=ImportSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Importa clientes em lote a partir de uma planilha")
async def import_customers_batch(
    file: UploadFile = File(...),
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db)) -> ImportSummaryResponse:
    """
    Importa clientes via planilha (.xlsx, .csv) de forma isolada por Tenant.

    Regras de Negócio:
    1. Valida a extensão do arquivo.
    2. Lê os dados via pandas sem carregar tudo desnecessariamente na memória.
    3. Normaliza os campos e valida dados obrigatórios por linha.
    4. Garante que clientes com e-mail já existente no tenant não sejam duplicados.
    5. Insere em lotes (batching) na base de dados dentro de uma transação.
    """

    # 1. Validação de extensão do arquivo
    filename = file.filename.lower()
    if not (filename.endswith(".xlsx") or filename.endswith(".csv")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Formato de arquivo inválido. Envie um arquivo .csv ou .xlsx"
        )

    # 2. Leitura do arquivo em memória
    contents = await file.read()
    try:
        if filename.endswith(".csv"):
            df = pd.read_csv(BytesIO(contents), dtype=str)
        else:
            df = pd.read_excel(BytesIO(contents), dtype=str)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Erro ao ler a planilha: {str(e)}"
        )

    # Limpa nomes de colunas e substitui NaN por None
    df.columns = df.columns.str.strip().str.lower()
    df = df.where(pd.notnull(df), None)

    # Colunas obrigatórias esperadas
    required_columns = {"name", "email"}
    if not required_columns.issubset(set(df.columns)):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"A planilha deve conter as colunas obrigatórias: {', '.join(required_columns)}"
        )

    # 3. Busca e-mails já existentes NO TENANT ATUAL para evitar duplicidade rápida
    existing_emails = set(
        email for (email,) in db.query(Customer.email).filter(Customer.tenant_id == tenant_id).all()
    )

    # Contadores e coletores para o resumo final
    created_count = 0
    skipped_count = 0
    failed_count = 0
    errors: List[ImportErrorDetail] = []

    batch_to_insert: List[Customer] = []
    seen_in_file: set = set()

    # 4. Iteração registro a registro
    for idx, row in df.iterrows():
        row_num = idx + 2  # Considera o cabeçalho como linha 1

        name = str(row.get("name", "")).strip() if row.get("name") else None
        email = str(row.get("email", "")).strip().lower() if row.get("email") else None
        phone = str(row.get("phone", "")).strip() if row.get("phone") else None

        # Validação básica de campos obrigatórios
        if not name or not email:
            failed_count += 1
            errors.append(ImportErrorDetail(
                row=row_num,
                email=email,
                error="Nome e E-mail são obrigatórios."
            ))
            continue

        # Validação de e-mail duplicado dentro do próprio arquivo
        if email in seen_in_file:
            skipped_count += 1
            continue
        seen_in_file.add(email)

        # Validação de e-mail já existente na base para este Tenant
        if email in existing_emails:
            skipped_count += 1
            continue

        # Montagem do objeto ORM com isolamento explícito de Tenant
        customer = Customer(
            tenant_id=tenant_id,
            name=name,
            email=email,
            phone=phone
        )

        batch_to_insert.append(customer)
        existing_emails.add(email)  # Atualiza cache local

        # Persistência em lote (Batch Insert)
        if len(batch_to_insert) >= BATCH_SIZE:
            try:
                db.bulk_save_objects(batch_to_insert)
                db.commit()
                created_count += len(batch_to_insert)
                batch_to_insert.clear()
            except Exception as exc:
                db.rollback()
                # Em caso de falha no lote, registra e descarta o lote
                failed_count += len(batch_to_insert)
                errors.append(ImportErrorDetail(
                    row=row_num,
                    email=None,
                    error=f"Falha na gravação em lote: {str(exc)}"
                ))
                batch_to_insert.clear()

    # Processa os registros remanescentes do último lote
    if batch_to_insert:
        try:
            db.bulk_save_objects(batch_to_insert)
            db.commit()
            created_count += len(batch_to_insert)
        except Exception as exc:
            db.rollback()
            failed_count += len(batch_to_insert)
            errors.append(ImportErrorDetail(
                row=0,
                email=None,
                error=f"Falha ao gravar lote final: {str(exc)}"
            ))

    total_processed = len(df)

    # 5. Retorno do resumo do processamento
    return ImportSummaryResponse(
        total_processed=total_processed,
        created_count=created_count,
        skipped_count=skipped_count,
        failed_count=failed_count,
        errors=errors
    )