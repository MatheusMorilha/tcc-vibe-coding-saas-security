from dataclasses import dataclass, asdict
from typing import Any
from uuid import UUID, uuid4
import json

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel


app= FastAPI()


# Simulação do banco compartilhado entre todos os tenants.
DRAFTS: dict[tuple[UUID, UUID], str] = {}


@dataclass
class Formulario:
    nome: str
    email: str
    telefone: str
    observacoes: str = ""


class RascunhoRequest(BaseModel):
    formulario: dict[str, Any]


def get_tenant_id(x_tenant_id: str = Header(...))-> UUID:
    try:
        return UUID(x_tenant_id)
    except ValueError:
        raise HTTPException(400,"Tenant inválido")


def reconstruir_formulario(data: dict[str, Any])-> Formulario:
    campos= {"nome", "email", "telefone", "observacoes"}

    if not campos.issuperset(data):
        raise HTTPException(400,"Campos inválidos")

    return Formulario(
        nome=data["nome"],
        email=data["email"],
        telefone=data["telefone"],
        observacoes=data.get("observacoes",""),
    )


@app.post("/formularios/rascunhos")
def salvar_rascunho(
    request: RascunhoRequest,
    x_tenant_id: str = Header(...),
):
    tenant_id= get_tenant_id(x_tenant_id)
    draft_id= uuid4()

    formulario= reconstruir_formulario(request.formulario)

    # A chave contém o tenant para impedir acesso cruzado entre empresas.
    DRAFTS[(tenant_id, draft_id)] = json.dumps(
        asdict(formulario),
        ensure_ascii=False,
    )

    return {
        "id": str(draft_id),
        "status": "saved",
    }


@app.get("/formularios/rascunhos/{draft_id}")
def restaurar_rascunho(
    draft_id: UUID,
    x_tenant_id: str = Header(...),
):
    tenant_id= get_tenant_id(x_tenant_id)

    payload= DRAFTS.get((tenant_id, draft_id))

    if payloadis None:
        raise HTTPException(404,"Rascunho não encontrado")

    dados= json.loads(payload)

    # Reconstrói o objeto original da aplicação.
    formulario= reconstruir_formulario(dados)

    return {
        "id": str(draft_id),
        "formulario": asdict(formulario),
    }