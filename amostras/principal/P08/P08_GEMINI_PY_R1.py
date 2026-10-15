from io import BytesIO
from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

app = FastAPI(title="SaaS Multi-tenant Export API")


# =====================================================================
# DUMMY / STUB MODELS E DEPENDÊNCIAS
# (Substitua pelos modelos e autenticação reais da sua aplicação)
# =====================================================================

class User:
    """Modelo de Usuário Autenticado."""
    def __init__(self, user_id: int, company_id: int, name: str):
        self.id = user_id
        self.company_id = company_id  # ID da empresa/tenant do usuário
        self.name = name


def get_db():
    """Dependency Provider para sessão do Banco de Dados."""
    db = None  # Instância do SessionLocal() do SQLAlchemy
    try:
        yield db
    finally:
        pass


def get_current_user() -> User:
    """
    Dependency Provider para obter o usuário logado via JWT/Bearer Token.
    Garante que as requisições contenham o tenant_id associado ao token.
    """
    # Exemplo: Retorna um usuário autenticado pertencente à empresa com ID 42
    return User(user_id=10, company_id=42, name="Gestor SaaS")


# =====================================================================
# ROTA DE EXPORTAÇÃO (MULTI-TENANT SAFE)
# =====================================================================

@app.get(
    "/api/v1/customers/export",
    summary="Exporta os dados cadastrais de clientes para planilha Excel",
    tags=["Clientes"])
def export_customers_excel(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    """
    Exporta apenas os clientes pertencentes à empresa (tenant) do usuário autenticado.
    Os dados são processados em memória e retornados como download de arquivo .xlsx.
    """
    import pandas as pd  # Importado sob demanda para performance de inicialização

    # 1. Consulta isolada por locatário (Multi-tenant filtering)
    # CRÍTICO: Sempre filtrar pelo company_id do usuário autenticado!
    #
    # Exemplo usando SQLAlchemy:
    # customers_query = db.query(Customer).filter(Customer.company_id == current_user.company_id).all()

    # Simulação de dados retornados do banco de dados para a empresa logada (company_id=42)
    customers_data = [
        {
            "id": 101,
            "company_id": 42,
            "nome_razao_social": "Empresa Alfa Ltda",
            "cpf_cnpj": "12.345.678/0001-90",
            "email": "contato@alfa.com",
            "telefone": "(11) 98765-4321",
            "cidade": "São Paulo",
            "uf": "SP",
            "status": "Ativo",
            "created_at": datetime(2025, 1, 15, 10, 30)
        },
        {
            "id": 102,
            "company_id": 42,
            "nome_razao_social": "João da Silva",
            "cpf_cnpj": "123.456.789-00",
            "email": "joao@email.com",
            "telefone": "(21) 99999-8888",
            "cidade": "Rio de Janeiro",
            "uf": "RJ",
            "status": "Ativo",
            "created_at": datetime(2025, 2, 20, 14, 15)
        }
    ]

    if not customers_data:
        raise HTTPException(
            status_code=status.HTTP_444_NO_RESPONSE,
            detail="Nenhum registro encontrado para exportação."
        )

    # 2. Transforma os dados em um DataFrame Pandas
    df = pd.DataFrame(customers_data)

    # Remove colunas internas/sensíveis antes de exportar
    colunas_para_remover = ["company_id"]
    df.drop(columns=[col for col in colunas_para_remover if col in df.columns], inplace=True)

    # Renomeia os cabeçalhos para exibição amigável na planilha
    df.rename(
        columns={
            "id": "Código",
            "nome_razao_social": "Nome / Razão Social",
            "cpf_cnpj": "CPF / CNPJ",
            "email": "E-mail",
            "telefone": "Telefone",
            "cidade": "Cidade",
            "uf": "UF",
            "status": "Status",
            "created_at": "Data de Cadastro"
        },
        inplace=True
    )

    # Formatando datas para exibição sem fuso horário textual
    if "Data de Cadastro" in df.columns:
        df["Data de Cadastro"] = df["Data de Cadastro"].dt.strftime("%d/%m/%Y %H:%M")

    # 3. Escreve a planilha Excel em um buffer de memória (sem salvar no disco)
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, sheet_name="Clientes", index=False)

        # Ajuste automático de largura das colunas
        worksheet = writer.sheets["Clientes"]
        for col in worksheet.columns:
            max_len = max(len(str(cell.value or '')) for cell in col)
            col_letter = col[0].column_letter
            worksheet.column_dimensions[col_letter].width = max(max_len + 3, 12)

    # Reposiciona o ponteiro do buffer no início
    output.seek(0)

    # 4. Gera o nome dinâmico do arquivo contendo a data da exportação
    filename = f"clientes_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

    # 5. Retorna o arquivo binário com os headers HTTP adequados para download
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"'
    }

    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers=headers
    )