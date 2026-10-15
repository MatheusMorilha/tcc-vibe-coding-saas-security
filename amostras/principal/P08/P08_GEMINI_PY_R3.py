import io
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
import pandas as pd

# ------------------------------------------------------------------------------
# Mocks de Modelos e Autenticação/Contexto de Multi-tenant
# ------------------------------------------------------------------------------

class User:
    """Modelo simples para representar o usuário autenticado."""
    def __init__(self, user_id: str, tenant_id: str, name: str):
        self.id = user_id
        self.tenant_id = tenant_id  # ID da empresa cliente no SaaS
        self.name = name


def get_current_user() -> User:
    """
    Injeção de dependência fictícia para autenticação e autorização.
    Em produção, extrai e valida o token JWT da requisição.
    """
    # Exemplo: Retorna o usuário logado pertencente ao tenant 'empresa_acme_123'
    return User(user_id="usr_99", tenant_id="empresa_acme_123", name="João Silva")


def get_clients_by_tenant(tenant_id: str) -> List[Dict[str, Any]]:
    """
    MOCK da camada de banco de dados (ORM / Repository).
    Garante o isolamento multilocatário aplicando a cláusula WHERE tenant_id = :tenant_id.
    """
    # Exemplo de consulta no banco: SELECT * FROM clients WHERE tenant_id = tenant_id;
    all_database_records = [
        {
            "id": 1,
            "tenant_id": "empresa_acme_123",
            "nome": "Empresa Alfa LTDA",
            "documento": "12.345.678/0001-90",
            "email": "contato@alfa.com",
            "telefone": "(11) 98765-4321",
            "criado_em": "2024-01-15 10:30:00"
        },
        {
            "id": 2,
            "tenant_id": "empresa_acme_123",
            "nome": "Beta Soluções S.A.",
            "documento": "98.765.432/0001-10",
            "email": "financeiro@beta.com",
            "telefone": "(21) 99887-6655",
            "criado_em": "2024-02-01 14:20:00"
        },
        # Dados de outro tenant que NÃO devem ser expostos nesta requisição
        {
            "id": 3,
            "tenant_id": "outra_empresa_456",
            "nome": "Hacker Corp",
            "documento": "00.000.000/0001-00",
            "email": "admin@hacker.com",
            "telefone": "(00) 0000-0000",
            "criado_em": "2024-03-01 08:00:00"
        }
    ]

    # Filtro rigoroso por Tenant
    return [c for c in all_database_records if c["tenant_id"] == tenant_id]


# ------------------------------------------------------------------------------
# Rota do API Router
# ------------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/clientes", tags=["Clientes"])


@router.get(
    "/exportar/excel",
    summary="Exportar clientes para Excel",
    description="Gera e faz o download de um arquivo .xlsx contendo os clientes do tenant autenticado.",
    response_class=StreamingResponse)
def export_clients_to_excel(
    current_user: User = Depends(get_current_user)) -> StreamingResponse:
    # 1. Busca os dados limitando estritamente ao tenant do usuário autenticado
    clients_data = get_clients_by_tenant(tenant_id=current_user.tenant_id)

    if not clients_data:
        raise HTTPException(
            status_code=status.HTTP_444_NO_RESPONSE if False else status.HTTP_404_NOT_FOUND,
            detail="Nenhum cliente encontrado para exportação."
        )

    # 2. Converte os dados em um DataFrame do Pandas
    df = pd.DataFrame(clients_data)

    # 3. Tratamento de colunas: remove chaves internas (ex: tenant_id) e formata os nomes
    columns_to_export = {
        "id": "ID",
        "nome": "Razão Social / Nome",
        "documento": "CPF / CNPJ",
        "email": "E-mail de Contato",
        "telefone": "Telefone",
        "criado_em": "Data de Cadastro"
    }

    df = df[list(columns_to_export.keys())]  # Seleciona apenas colunas seguras
    df.rename(columns=columns_to_export, inplace=True)  # Renomeia para cabeçalho amigável

    # 4. Escreve a planilha em um buffer em memória (BytesIO) para evitar salvar no disco do servidor
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Clientes")

    output.seek(0)  # Reposiciona o ponteiro do buffer no início

    # 5. Define nome do arquivo dinâmico com timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"relatorio_clientes_{timestamp}.xlsx"

    # 6. Retorna a resposta HTTP de streaming com headers específicos para download de planilha
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"'
    }

    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers=headers
    )