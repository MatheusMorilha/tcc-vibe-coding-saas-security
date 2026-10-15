from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from pydantic import BaseModel, ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, declarative_base, sessionmaker
import json

DATABASE_URL= "postgresql+psycopg2://user:password@localhost/saas"

engine= create_engine(DATABASE_URL)
SessionLocal= sessionmaker(bind=engine)
Base= declarative_base()

app= FastAPI()


class Account(Base):
    __tablename__= "accounts"

    # Exemplo simplificado
    id = ...
    tenant_id= ...
    plan= ...
    timezone= ...
    language= ...


class Configuration(BaseModel):
    timezone: str | None = None
    language: str | None = None


def get_db():
    db= SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_tenant_id()-> int:
    # Em produção, obtenha o tenant a partir do JWT/sessão autenticada.
    raise NotImplementedError


@app.post("/api/account/configuration")
async def upload_configuration(
    file: UploadFile= File(...),
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session= Depends(get_db),
):
    if file.content_type!= "application/json":
        raise HTTPException(
            status_code=415,
            detail="O arquivo deve ser JSON."
        )

    raw= await file.read()

    if len(raw) > 1_000_000:
        raise HTTPException(
            status_code=413,
            detail="Arquivo excede o limite permitido."
        )

    try:
        payload= json.loads(raw.decode("utf-8"))
        config= Configuration.model_validate(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError):
        raise HTTPException(
            status_code=400,
            detail="Arquivo de configuração inválido."
        )

    # O tenant vem da autenticação, não do arquivo enviado.
    account= db.scalar(
        select(Account)
        .where(Account.tenant_id== tenant_id)
        .with_for_update()
    )

    if accountis None:
        raise HTTPException(
            status_code=404,
            detail="Conta não encontrada."
        )

    # Nunca aceitar tenant_id/account_id fornecido pelo cliente
    # para decidir qual conta será alterada.
    if config.timezoneis not None:
        account.timezone= config.timezone

    if config.languageis not None:
        account.language= config.language

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Não foi possível aplicar a configuração."
        )

    return {
        "message": "Configuração aplicada com sucesso.",
        "tenant_id": tenant_id,
    }