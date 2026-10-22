from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
import io
import pandas as pd
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import List, Dict, Any

router = APIRouter(prefix="/api/v1/customers", tags=["Customers Import"])

class ImportSummaryResponse(BaseModel):
    total_processed: int
    success_count: int
    error_count: int
    errors: List[Dict[str, Any]]

# Dependência simulada para recuperar o tenant_id do contexto de autenticação/token JWT
def get_current_tenant_id() -> int:
    # Em produção, isso viria do token JWT do usuário logado
    return 1 

# Dependência simulada de sessão do banco de dados
def get_db():
    # yield db_session
    pass

@router.post("/import", response_model=ImportSummaryResponse, status_code=status.HTTP_200_OK)
async def import_customers_batch(
    file: UploadFile = File(...),
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db)
):
    """
    Importa uma planilha de clientes (CSV ou Excel) em lote para a empresa autenticada,
    garantindo o isolamento dos dados via tenant_id.
    """
    # Validação da extensão do arquivo
    filename = file.filename.lower()
    contents = await file.read()
    
    try:
        if filename.endswith(".csv"):
            df = pd.read_csv(io.BytesIO(contents))
        elif filename.endswith((".xls", ".xlsx")):
            df = pd.read_excel(io.BytesIO(contents))
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Formato de arquivo inválido. Apenas arquivos CSV ou Excel (.xls, .xlsx) são permitidos."
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Não foi possível ler o arquivo enviado: {str(e)}"
        )

    # Validação de colunas obrigatórias
    required_columns = {"name", "email", "document"}
    if not required_columns.issubset(df.columns):
        missing = required_columns - set(df.columns)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Colunas obrigatórias ausentes na planilha: {list(missing)}"
        )

    success_count = 0
    error_count = 0
    errors = []

    # Iteração sobre os registros do DataFrame
    for index, row in df.iterrows():
        row_number = index + 2  # Considerando o cabeçalho na linha 1
        
        try:
            # Limpeza básica de dados
            name = str(row.get("name", "")).strip()
            email = str(row.get("email", "")).strip()
            document = str(row.get("document", "")).strip()

            if not name or not email:
                raise ValueError("Nome e e-mail são obrigatórios.")

            # Regra de negócio: Verificar duplicidade por e-mail ou documento dentro do mesmo tenant
            # existing_customer = db.query(Customer).filter_by(tenant_id=tenant_id, email=email).first()
            # if existing_customer:
            #     raise ValueError(f"Cliente com o e-mail {email} já cadastrado.")

            # Criação da entidade associada ao tenant atual
            # new_customer = Customer(
            #     tenant_id=tenant_id,
            #     name=name,
            #     email=email,
            #     document=document
            # )
            # db.add(new_customer)
            # db.commit()
            
            success_count += 1

        except Exception as e:
            # Em caso de erro em uma linha específica, faz o rollback parcial da linha 
            # e registra o erro sem interromper o lote inteiro.
            # db.rollback()
            error_count += 1
            errors.append({
                "row": row_number,
                "data": row.to_dict(),
                "error": str(e)
            })

    return {
        "total_processed": len(df),
        "success_count": success_count,
        "error_count": error_count,
        "errors": errors
    }