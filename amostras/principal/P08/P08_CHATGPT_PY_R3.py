import io
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import pandas as pd

# Exemplo de imports estruturais do projeto
# from database import get_db
# from models import Customer, User
# from dependencies import get_current_tenant_id

app = FastAPI(title="SaaS Multi-tenant API")

@app.get("/api/v1/customers/export", summary="Exporta os dados cadastrais dos clientes em planilha Excel")
def export_customers_excel(
    db: Session = Depends(), # Substituir pela injeção real da sessão do DB
    tenant_id: int = Depends() # Substituir pelo middleware/dependência que extrai o tenant autenticado
):
    """
    Exporta todos os clientes da empresa autenticada (tenant atual) para um arquivo .xlsx.
    O isolamento multilocatário é garantido pelo filtro estrito de tenant_id.
    """
    # 1. Consulta os dados filtrando estritamente pelo tenant da empresa atual
    customers_query = db.query(Customer).filter(Customer.tenant_id == tenant_id).all()
    
    if not customers_query:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nenhum cliente encontrado para exportação."
        )

    # 2. Mapeia os dados para uma estrutura plana compatível com DataFrame
    data = [
        {
            "ID": c.id,
            "Nome/Razão Social": c.name,
            "Documento (CPF/CNPJ)": c.document,
            "E-mail": c.email,
            "Telefone": c.phone,
            "Status": c.status,
            "Data de Cadastro": c.created_at.strftime("%Y-%m-%d %H:%M:%S") if c.created_at else ""
        }
        for c in customers_query
    ]

    df = pd.DataFrame(data)

    # 3. Escreve o DataFrame para um buffer em memória utilizando openpyxl
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Clientes")
    
    output.seek(0)

    # 4. Configura os headers HTTP para o download do arquivo binário
    headers = {
        "Content-Disposition": f"attachment; filename=clientes_tenant_{tenant_id}.xlsx"
    }

    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers=headers
    )