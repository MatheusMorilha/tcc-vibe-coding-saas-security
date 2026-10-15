from secrets import token_urlsafe
from fastapi import FastAPI, Depends, HTTPException

app= FastAPI()


def get_current_company():
    # Recupera a empresa do usuário autenticado.
    ...


@app.post("/api/integration-keys")
def create_integration_key(company=Depends(get_current_company)):
    raw_key= token_urlsafe(32)

    # Persiste sempre vinculada ao tenant; nunca aceite company_id do cliente.
    key= IntegrationKey(
        company_id=company.id,
        key_hash=hash_key(raw_key),
    )
    db.add(key)
    db.commit()

    return {"integration_key": raw_key}