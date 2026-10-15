"""
POST /api/v1/account/settings/import
Importa um arquivo de configuração (JSON ou YAML) e aplica à conta
da empresa autenticada.

Dependências: fastapi, pydantic>=2, pyyaml, sqlalchemy>=2
"""
from __future__ import annotations

import json
import logging
from enum import Enum
from typing import Annotated, Any, Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy.orm import Session

# --- Dependências do projeto (assumidas existentes) -------------------------
# get_db: fornece a Session do SQLAlchemy
# get_current_user: valida o JWT/sessão e devolve o usuário autenticado
# models: Company, CompanySettings, AuditLog
from app.deps import get_db, get_current_user
from app.models import AuditLog, Company, CompanySettings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/account/settings", tags=["settings"])

MAX_FILE_BYTES = 64 * 1024          # 64 KB é muito para um arquivo de config
MAX_YAML_ALIASES_GUARD = True       # veja _parse_yaml_seguro
ALLOWED_EXTENSIONS = {".json", ".yaml", ".yml"}


# --------------------------------------------------------------------------
# Schema: lista branca explícita do que o cliente PODE configurar.
# Campos como tenant_id, plano, limites, is_admin etc. NÃO existem aqui;
# com extra="forbid", se vierem no arquivo a requisição é rejeitada.
# --------------------------------------------------------------------------
class Idioma(str, Enum):
    PT_BR = "pt-BR"
    EN_US = "en-US"
    ES_ES = "es-ES"


class NotificacoesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email_resumo_diario: bool = False
    email_alertas_financeiros: bool = True
    emails_destinatarios: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("emails_destinatarios")
    @classmethod
    def _validar_emails(cls, v: list[str]) -> list[str]:
        for e in v:
            if len(e) > 254 or "@" not in e or e.startswith("@") or e.endswith("@"):
                raise ValueError(f"E-mail inválido: {e[:50]!r}")
        return [e.strip().lower() for e in v]


class ConfiguracaoEmpresa(BaseModel):
    model_config = ConfigDict(extra="forbid")

    versao_schema: int = Field(1, ge=1, le=1)
    nome_exibicao: Optional[str] = Field(None, min_length=2, max_length=120)
    idioma: Idioma = Idioma.PT_BR
    fuso_horario: str = Field("America/Sao_Paulo", max_length=64)
    moeda: str = Field("BRL", pattern=r"^[A-Z]{3}$")
    inicio_ano_fiscal_mes: int = Field(1, ge=1, le=12)
    exigir_2fa: bool = False
    sessao_expira_minutos: int = Field(60, ge=5, le=1440)
    notificacoes: NotificacoesConfig = Field(default_factory=NotificacoesConfig)

    @field_validator("fuso_horario")
    @classmethod
    def _validar_fuso(cls, v: str) -> str:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("Fuso horário inválido")
        return v


class ImportResultado(BaseModel):
    status: str
    campos_aplicados: list[str]


# --------------------------------------------------------------------------
# Parsing seguro
# --------------------------------------------------------------------------
def _parse_yaml_seguro(texto: str) -> Any:
    # safe_load: não instancia objetos Python arbitrários (evita RCE).
    # Rejeitamos âncoras/aliases para evitar "billion laughs" (DoS por expansão).
    if MAX_YAML_ALIASES_GUARD:
        for evento in yaml.parse(texto):
            if isinstance(evento, yaml.AliasEvent):
                raise ValueError("Aliases YAML não são permitidos")
    return yaml.safe_load(texto)


def _interpretar_arquivo(nome: str, bruto: bytes) -> dict[str, Any]:
    try:
        texto = bruto.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("O arquivo deve estar codificado em UTF-8")

    try:
        if nome.lower().endswith(".json"):
            dados = json.loads(texto)
        else:
            dados = _parse_yaml_seguro(texto)
    except (json.JSONDecodeError, yaml.YAMLError, RecursionError) as exc:
        raise ValueError(f"Sintaxe inválida: {type(exc).__name__}")

    if not isinstance(dados, dict):
        raise ValueError("A raiz do arquivo deve ser um objeto/mapa")
    return dados


async def _ler_com_limite(arquivo: UploadFile) -> bytes:
    # Lê no máximo MAX+1 bytes: não carrega arquivos gigantes em memória.
    bruto = await arquivo.read(MAX_FILE_BYTES + 1)
    if len(bruto) > MAX_FILE_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Arquivo excede {MAX_FILE_BYTES // 1024} KB",
        )
    if not bruto:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Arquivo vazio")
    return bruto


# --------------------------------------------------------------------------
# Rota
# --------------------------------------------------------------------------
@router.post(
    "/import",
    response_model=ImportResultado,
    status_code=status.HTTP_200_OK,
)
async def importar_configuracao(
    arquivo: UploadFile,
    usuario: Annotated[Any, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> ImportResultado:
    # 1) Autorização: apenas administradores da própria empresa.
    if not usuario.is_company_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente")

    # 2) Tenant SEMPRE derivado da identidade autenticada, nunca do arquivo.
    tenant_id = usuario.company_id

    # 3) Validação básica do upload (extensão + tamanho).
    nome = (arquivo.filename or "").lower()
    if not any(nome.endswith(ext) for ext in ALLOWED_EXTENSIONS):
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            "Formatos aceitos: .json, .yaml, .yml",
        )
    bruto = await _ler_com_limite(arquivo)

    # 4) Parsing + validação por schema (lista branca).
    try:
        dados = _interpretar_arquivo(nome, bruto)
        config = ConfiguracaoEmpresa.model_validate(dados)
    except ValueError as exc:  # inclui ValidationError do Pydantic v2
        if isinstance(exc, ValidationError):
            detalhes = [
                {"campo": ".".join(map(str, e["loc"])), "erro": e["msg"]}
                for e in exc.errors(include_input=False, include_url=False)
            ]
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detalhes)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    # 5) Regras de negócio dependentes do plano de assinatura.
    empresa: Company | None = (
        db.query(Company).filter(Company.id == tenant_id).one_or_none()
    )
    if empresa is None or not empresa.assinatura_ativa:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa")

    if config.exigir_2fa and not empresa.plano.permite_2fa:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Seu plano não inclui autenticação em dois fatores"
        )
    if len(config.notificacoes.emails_destinatarios) > empresa.plano.max_destinatarios:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"Seu plano permite até {empresa.plano.max_destinatarios} destinatários",
        )

    # 6) Aplicação atômica, sempre filtrada por tenant_id.
    novos_valores = config.model_dump(mode="json", exclude={"versao_schema"})
    try:
        registro = (
            db.query(CompanySettings)
            .filter(CompanySettings.company_id == tenant_id)
            .with_for_update()               # evita corrida entre dois imports
            .one_or_none()
        )
        if registro is None:
            registro = CompanySettings(company_id=tenant_id)
            db.add(registro)

        antigos = {k: getattr(registro, k, None) for k in novos_valores}
        for campo, valor in novos_valores.items():
            setattr(registro, campo, valor)   # só campos da lista branca

        db.add(
            AuditLog(
                company_id=tenant_id,
                user_id=usuario.id,
                acao="settings.import",
                detalhes={"antes": antigos, "depois": novos_valores},
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Falha ao aplicar configuração (tenant=%s)", tenant_id)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "Não foi possível aplicar a configuração"
        )

    return ImportResultado(status="aplicado", campos_aplicados=sorted(novos_valores))