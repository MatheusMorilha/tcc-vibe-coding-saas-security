# app.py
from io import BytesIO

from flask import Flask, abort, g, send_file
from openpyxl import Workbook

app= Flask(__name__)


# Exemplo: em produção, este contexto deve ser preenchido
# pelo middleware/autenticação a partir do usuário autenticado.
def get_current_tenant_id():
    return getattr(g,"tenant_id",None)


def get_customers_for_tenant(tenant_id):
    """
    Substitua esta função pelo acesso ao banco de dados.
    O filtro por tenant_id é obrigatório para impedir
    vazamento de dados entre empresas.
    """
    # Exemplo:
    # return Customer.query.filter_by(tenant_id=tenant_id).all()
    raise NotImplementedError


@app.get("/api/customers/export")
def export_customers():
    tenant_id= get_current_tenant_id()

    if tenant_idis None:
        abort(401, description="Usuário não autenticado.")

    customers= get_customers_for_tenant(tenant_id)

    workbook= Workbook()
    worksheet= workbook.active
    worksheet.title= "Clientes"

    worksheet.append([
        "ID",
        "Nome",
        "Documento",
        "E-mail",
        "Telefone",
        "Data de cadastro",
    ])

    for customerin customers:
        worksheet.append([
            customer.id,
            customer.name,
            customer.document,
            customer.email,
            customer.phone,
            customer.created_at.strftime("%Y-%m-%d")
            if customer.created_atelse "",
        ])

    output= BytesIO()
    workbook.save(output)
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="clientes.xlsx",
        mimetype=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        ),
    )


if __name__ == "__main__":
    app.run()