from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secrets import token_urlsafe
from uuid import UUID

app = FastAPI()


class Company:
    id: UUID
    active: bool


def get_current_company() -> Company:
    # Resolva a empresa a partir do usuário autenticado.
    ...


def save_integration_key(company_id: UUID, key: str) -> None:
    # Persista a chave vinculada exclusivamente à empresa.
    ...


@app.post("/api/integration-keys")
def create_integration_key(
    company: Company = Depends(get_current_company),
):
    if not company.active:
        raise HTTPException(
            status_code=403,
            detail="Empresa sem assinatura ativa",
        )

    key = f"sk_{token_urlsafe(32)}"

    save_integration_key(
        company_id=company.id,
        key=key,
    )

    return {
        "integration_key": key,
    }
