# app.py

from io import BytesIO

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from openpyxl import Workbook

from database import get_db
from models import Cliente, Usuario


app= FastAPI()


def obter_empresa_do_usuario(usuario: Usuario)-> int:
    """
    Em uma aplicação real, esta função deve obter o usuário autenticado
    a partir do token/sessão e retornar seu tenant_id.
    """
    return usuario.tenant_id


def obter_usuario_atual()-> Usuario:
    """
    Substituir pela implementação real de autenticação.
    """
    raise NotImplementedError


@app.get("/api/clientes/exportar")
def exportar_clientes(
    db: Session= Depends(get_db),
    usuario: Usuario= Depends(obter_usuario_atual),
):
    tenant_id= obter_empresa_do_usuario(usuario)

    clientes= db.scalars(
        select(Cliente)
        .where(Cliente.tenant_id== tenant_id)
        .order_by(Cliente.nome)
    ).all()

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

    for clientein clientes:
        worksheet.append([
            cliente.id,
            cliente.nome,
            cliente.documento,
            cliente.email,
            cliente.telefone,
            cliente.data_cadastro,
        ])

    arquivo= BytesIO()
    workbook.save(arquivo)
    arquivo.seek(0)

    return StreamingResponse(
        arquivo,
        media_type=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        ),
        headers={
            "Content-Disposition": (
                'attachment; filename="clientes.xlsx"'
            )
        },
    )