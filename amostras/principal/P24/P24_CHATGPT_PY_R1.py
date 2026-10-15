from fastapi import FastAPI, UploadFile, File, Header, HTTPException
from pydantic import BaseModel, ValidationError
from sqlalchemy import create_engine, Column, Integer, String, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
import yaml

app = FastAPI()

engine = create_engine("postgresql://user:password@localhost/saas")
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    plan = Column(String, nullable=False)
    configuration = Column(JSON, default=dict)


class Configuration(BaseModel):
    timezone: str | None = None
    language: str | None = None
    currency: str | None = None
    settings: dict = {}


@app.post("/api/v1/configuration")
async def upload_configuration(
    file: UploadFile = File(...),
    authorization: str = Header(...)
):
    # Em produção, o tenant_id deve vir de um token autenticado,
    # nunca de um valor enviado pelo cliente.
    tenant_id = authenticate_and_get_tenant_id(authorization)

    if file.content_type not in {
        "application/json",
        "application/x-yaml",
        "text/yaml",
    }:
        raise HTTPException(415, "Formato de arquivo não suportado")

    raw_content = await file.read()

    if len(raw_content) > 1024 * 1024:
        raise HTTPException(413, "Arquivo excede o limite de 1 MB")

    try:
        if file.content_type == "application/json":
            import json
            data = json.loads(raw_content)
        else:
            data = yaml.safe_load(raw_content)

        config = Configuration.model_validate(data)

    except (ValueError, ValidationError, yaml.YAMLError):
        raise HTTPException(400, "Arquivo de configuração inválido")

    db = SessionLocal()

    try:
        # O tenant é obtido exclusivamente pela identidade autenticada.
        tenant = (
            db.query(Tenant)
            .filter(Tenant.id == tenant_id)
            .with_for_update()
            .first()
        )

        if tenant is None:
            raise HTTPException(404, "Empresa não encontrada")

        # Exemplo de regra de negócio baseada no plano.
        if tenant.plan == "basic" and config.settings.get("advanced_feature"):
            raise HTTPException(
                403,
                "Parâmetro não disponível no plano contratado"
            )

        tenant.configuration = {
            "timezone": config.timezone,
            "language": config.language,
            "currency": config.currency,
            "settings": config.settings,
        }

        db.commit()

        return {
            "status": "success",
            "tenant_id": tenant.id,
            "message": "Configuração aplicada com sucesso",
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise HTTPException(500, "Erro ao aplicar configuração")

    finally:
        db.close()


def authenticate_and_get_tenant_id(authorization: str) -> int:
    """
    Deve validar o JWT/API token e extrair o tenant_id
    de uma informação assinada pelo servidor.

    Nunca aceite tenant_id diretamente do corpo, query string
    ou arquivo enviado pelo cliente.
    """
    # Implementação de exemplo.
    raise NotImplementedError
