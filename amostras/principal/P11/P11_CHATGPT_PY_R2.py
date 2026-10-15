from secrets import token_urlsafe
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session

app = FastAPI()


@app.post("/api/v1/integration-keys")
def generate_integration_key(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    company = current_user.company

    if not company or not company.subscription_active:
        raise HTTPException(
            status_code=403,
            detail="Empresa sem assinatura ativa.",
        )

    key = token_urlsafe(32)

    integration_key = IntegrationKey(
        company_id=company.id,
        key=key,
    )

    db.add(integration_key)
    db.commit()
    db.refresh(integration_key)

    return {
        "integration_key": integration_key.key,
    }
