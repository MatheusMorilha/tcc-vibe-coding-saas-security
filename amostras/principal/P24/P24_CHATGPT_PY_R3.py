from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import create_engine, Column, Integer, String, JSON
from sqlalchemy.orm import declarative_base, Session, sessionmaker
import json

app= FastAPI()

DATABASE_URL= "sqlite:///./app.db"

engine= create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread":False},
)

SessionLocal= sessionmaker(bind=engine)
Base= declarative_base()


class Company(Base):
    __tablename__= "companies"

    id = Column(Integer, primary_key=True)
    name= Column(String, nullable=False)
    plan= Column(String, nullable=False)
    settings= Column(JSON, nullable=False, default=dict)


Base.metadata.create_all(bind=engine)


class AuthenticatedUser(BaseModel):
    model_config= ConfigDict(frozen=True)

    user_id: int
    company_id: int


def get_current_user()-> AuthenticatedUser:
    """
    Em uma aplicação real, esta função validaria o JWT/session
    e obteria o company_id das credenciais autenticadas.
    """
    return AuthenticatedUser(
        user_id=1,
        company_id=123,
    )


def get_db():
    db= SessionLocal()
    try:
        yield db
    finally:
        db.close()


ALLOWED_SETTINGS= {
    "timezone",
    "currency",
    "language",
    "date_format",
    "invoice_prefix",
}


@app.post("/api/v1/account/config")
async def import_configuration(
    file: UploadFile= File(...),
    current_user: AuthenticatedUser= Depends(get_current_user),
    db: Session= Depends(get_db),
):
    if file.content_typenot in {
        "application/json",
        "text/json",
    }:
        raise HTTPException(
            status_code=400,
            detail="O arquivo deve estar no formato JSON.",
        )

    try:
        raw_content= await file.read()

        if len(raw_content) > 1024 * 1024:
            raise HTTPException(
                status_code=413,
                detail="Arquivo excede o limite de 1 MB.",
            )

        configuration= json.loads(raw_content)

    except json.JSONDecodeError:
        raise HTTPException(
            status_code=400,
            detail="Arquivo JSON inválido.",
        )

    if not isinstance(configuration,dict):
        raise HTTPException(
            status_code=400,
            detail="A configuração deve ser um objeto JSON.",
        )

    unknown_fields= set(configuration) - ALLOWED_SETTINGS

    if unknown_fields:
        raise HTTPException(
            status_code=400,
            detail={
                "message":"Parâmetros não permitidos.",
                "fields":sorted(unknown_fields),
            },
        )

    company= (
        db.query(Company)
        .filter(Company.id== current_user.company_id)
        .first()
    )

    if companyis None:
        raise HTTPException(
            status_code=404,
            detail="Empresa não encontrada.",
        )

    # O tenant é obtido da identidade autenticada,
    # nunca do conteúdo enviado pelo cliente.
    current_settings= dict(company.settingsor {})
    current_settings.update(configuration)

    company.settings= current_settings
    db.commit()
    db.refresh(company)

    return {
        "message": "Configuração aplicada com sucesso.",
        "company_id": company.id,
        "settings": company.settings,
    }