import json
from typing import Annotated

from fastapi import (
    FastAPI,
    UploadFile,
    File,
    Depends,
    HTTPException,
    status,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import (
    create_engine,
    String,
    Integer,
    JSON,
    select,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    sessionmaker,
    Session,
)

# --------------------------------------------------
# Configuração da aplicação e do banco de dados
# --------------------------------------------------

app = FastAPI(title="SaaS Configuration API")

DATABASE_URL = "sqlite:///./saas.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


class AccountConfiguration(Base):
    __tablename__ = "account_configurations"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )
    tenant_id: Mapped[int] = mapped_column(
        Integer, unique=True, nullable=False, index=True
    )
    settings: Mapped[dict] = mapped_column(
        JSON, nullable=False, default=dict
    )


Base.metadata.create_all(bind=engine)


# --------------------------------------------------
# Dependências de acesso
# --------------------------------------------------

class CurrentUser(BaseModel):
    user_id: int
    tenant_id: int
    can_manage_configuration: bool


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user() -> CurrentUser:
    """
    Substitua por autenticação real, por exemplo,
    validação de JWT e consulta ao usuário no banco.
    Não aceite o tenant_id diretamente do arquivo.
    """
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Autenticação não configurada.",
    )


# --------------------------------------------------
# Esquema permitido para as configurações
# --------------------------------------------------

class ConfigurationSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timezone: str = Field(min_length=1, max_length=64)
    language: str = Field(min_length=2, max_length=10)
    notifications_enabled: bool
    session_timeout_minutes: int = Field(
        ge=5,
        le=1440,
    )


# --------------------------------------------------
# Endpoint de importação
# --------------------------------------------------

MAX_FILE_SIZE = 64 * 1024


@app.post("/api/v1/account/configuration/import")
def import_configuration(
    file: Annotated[UploadFile, File(...)],
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[CurrentUser, Depends(get_current_user)],
):
    # 1. Verificar autorização
    if not user.can_manage_configuration:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sem permissão para alterar configurações.",
        )

    # 2. Verificar o nome e o formato do arquivo
    if not file.filename or not file.filename.lower().endswith(
        ".json"
    ):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Envie um arquivo com extensão .json.",
        )

    # 3. Ler com limite de tamanho
    try:
        content = file.file.read(MAX_FILE_SIZE + 1)

        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="O arquivo excede o limite de 64 KB.",
            )

        if not content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="O arquivo está vazio.",
            )

        # 4. Interpretar JSON
        try:
            raw_config = json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Arquivo JSON inválido.",
            )

        if not isinstance(raw_config, dict):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="A configuração deve ser um objeto JSON.",
            )

        # 5. Validar campos e valores
        try:
            validated = ConfigurationSchema.model_validate(
                raw_config
            )
        except ValidationError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "message": "Configuração inválida.",
                    "errors": exc.errors(
                        include_input=False
                    ),
                },
            )

        settings = validated.model_dump()

        # 6. Consultar exclusivamente o locatário autenticado
        statement = select(AccountConfiguration).where(
            AccountConfiguration.tenant_id == user.tenant_id
        )

        account_config = db.scalar(statement)

        # 7. Criar ou atualizar a configuração
        if account_config is None:
            account_config = AccountConfiguration(
                tenant_id=user.tenant_id,
                settings=settings,
            )
            db.add(account_config)
        else:
            account_config.settings = settings

        # 8. Persistir de forma transacional
        db.commit()

        return {
            "message": "Configuração importada com sucesso.",
            "tenant_id": user.tenant_id,
            "configuration": settings,
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        # Registrar detalhes internamente, sem expor
        # informações sensíveis ao cliente.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível aplicar a configuração.",
        )

    finally:
        file.file.close()