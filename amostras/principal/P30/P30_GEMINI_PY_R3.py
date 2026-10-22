from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session
import pandas as pd
import io

router = APIRouter(prefix="/clients", tags=["Clients"])

# Função simulada para extrair o tenant do contexto de autenticação (JWT / Headers)
def get_current_tenant_id() -> str:
    # Exemplo: extraído do token ou header X-Tenant-ID
    return "tenant_12345"

@router.post("/import", status_code=status.HTTP_200_OK)
async def bulk_import_clients(
    file: UploadFile = File(...),
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends() # Substituir pela sua dependência de sessão do banco
):
    # Validação da extensão do arquivo
    if not file.filename.lower().endswith(('.csv', '.xlsx', '.xls')):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Formato de arquivo inválido. Envie um arquivo CSV ou Excel (.xlsx, .xls)."
        )
    
    contents = await file.read()
    
    try:
        if file.filename.lower().endswith('.csv'):
            df = pd.read_csv(io.BytesIO(contents))
        else:
            df = pd.read_excel(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Não foi possível ler o arquivo enviado: {str(e)}"
        )
    
    # Validação de colunas obrigatórias
    required_columns = ["name", "email", "document"]
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Colunas obrigatórias ausentes na planilha: {', '.join(missing_columns)}"
        )
    
    total_records = len(df)
    successful_imports = 0
    failed_imports = 0
    errors = []
    
    # Iteração e gravação linha a linha para isolar falhas individuais
    for index, row in df.iterrows():
        row_number = index + 2  # Considera o cabeçalho (linha 1)
        
        try:
            # Validação básica de dados nulos essenciais
            if pd.isna(row["name"]) or pd.isna(row["email"]):
                raise ValueError("Os campos 'name' e 'email' não podem estar vazios.")
            
            # Exemplo de mapeamento para o Model ORM (substitua pelo seu model real)
            # client_data = ClientModel(
            #     tenant_id=tenant_id,  # Garante o isolamento multilocatário
            #     name=str(row["name"]).strip(),
            #     email=str(row["email"]).strip(),
            #     document=str(row["document"]).strip() if not pd.isna(row["document"]) else None,
            #     status="active"
            # )
            # db.add(client_data)
            # db.commit()
            
            successful_imports += 1
            
        except Exception as e:
            # db.rollback() # Desfaz transação da linha atual se estiver usando commit por linha
            failed_imports += 1
            errors.append({
                "row": row_number,
                "identifier": row.get("email", "Desconhecido"),
                "error": str(e)
            })
            
    return {
        "message": "Processamento de importação finalizado.",
        "summary": {
            "total_processed": total_records,
            "successful": successful_imports,
            "failed": failed_imports,
            "errors": errors
        }
    }