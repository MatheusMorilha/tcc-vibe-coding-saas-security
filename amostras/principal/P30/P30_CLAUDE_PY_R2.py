"""
POST /api/v1/clientes/importacao

Importa em lote uma planilha (CSV ou XLSX) de clientes para a empresa
do usuário autenticado e devolve um resumo do processamento.

Premissas (ajuste aos nomes reais do seu projeto):
  - app.core.deps.get_db            -> Session do SQLAlchemy
  - app.core.deps.get_current_user  -> usuário autenticado (com .id, .empresa_id, .permissoes)
  - Modelos Empresa, Plano, Cliente
  - Constraint única em clientes (empresa_id, documento)
"""
import csv
import io
import logging
import re
from typing import Iterator, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from openpyxl import load_workbook
from pydantic import BaseModel, EmailStr, ValidationError, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, get_db
from app.models import Cliente, Empresa, Plano

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/clientes", tags=["clientes"])

# ----------------------------------------------------------------------------
# Limites defensivos
# ----------------------------------------------------------------------------
MAX_BYTES = 5 * 1024 * 1024          # 5 MB
MAX_LINHAS = 5_000                   # acima disso, usar processamento assíncrono
MAX_ERROS_NO_RESUMO = 100            # evita resposta gigante
TAMANHO_LOTE = 500
EXTENSOES_PERMITIDAS = {".csv", ".xlsx"}

COLUNAS_OBRIGATORIAS = {"nome", "documento"}
COLUNAS_ACEITAS = {"nome", "documento", "email", "telefone"}  # allowlist


# ----------------------------------------------------------------------------
# Schemas
# ----------------------------------------------------------------------------
class LinhaCliente(BaseModel):
    """Valida e normaliza uma linha. Apenas campos da allowlist chegam aqui."""
    nome: str
    documento: str
    email: Optional[EmailStr] = None
    telefone: Optional[str] = None

    @field_validator("nome")
    @classmethod
    def _nome(cls, v: str) -> str:
        v = _limpar_texto(v)
        if not (2 <= len(v) <= 150):
            raise ValueError("nome deve ter entre 2 e 150 caracteres")
        return v

    @field_validator("documento")
    @classmethod
    def _documento(cls, v: str) -> str:
        digitos = re.sub(r"\D", "", v or "")
        if len(digitos) not in (11, 14):  # CPF ou CNPJ
            raise ValueError("documento deve ter 11 (CPF) ou 14 (CNPJ) dígitos")
        return digitos

    @field_validator("email", "telefone", mode="before")
    @classmethod
    def _vazio_para_none(cls, v):
        return None if v is None or str(v).strip() == "" else str(v).strip()

    @field_validator("telefone")
    @classmethod
    def _telefone(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        digitos = re.sub(r"\D", "", v)
        if not (10 <= len(digitos) <= 13):
            raise ValueError("telefone inválido")
        return digitos


class ErroLinha(BaseModel):
    linha: int
    motivo: str


class ResumoImportacao(BaseModel):
    total_linhas: int
    importados: int
    duplicados: int
    rejeitados_por_limite_do_plano: int
    com_erro: int
    erros: list[ErroLinha]
    erros_truncados: bool


# ----------------------------------------------------------------------------
# Utilitários
# ----------------------------------------------------------------------------
def _limpar_texto(valor: str) -> str:
    """Remove caracteres de controle e neutraliza injeção de fórmula (CSV/Excel)."""
    v = re.sub(r"[\x00-\x1f\x7f]", " ", str(valor)).strip()
    if v and v[0] in ("=", "+", "-", "@"):
        v = "'" + v
    return v


def _ler_upload(arquivo: UploadFile) -> bytes:
    """Lê o arquivo em partes, abortando se passar do limite (não confia em Content-Length)."""
    buf = bytearray()
    while chunk := arquivo.file.read(64 * 1024):
        buf.extend(chunk)
        if len(buf) > MAX_BYTES:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"Arquivo excede o limite de {MAX_BYTES // (1024 * 1024)} MB.",
            )
    if not buf:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Arquivo vazio.")
    return bytes(buf)


def _normalizar_cabecalho(c) -> str:
    return re.sub(r"\s+", "_", str(c or "").strip().lower())


def _iterar_csv(conteudo: bytes) -> Iterator[tuple[int, dict]]:
    try:
        texto = conteudo.decode("utf-8-sig")
    except UnicodeDecodeError:
        texto = conteudo.decode("latin-1")
    amostra = texto[:4096]
    try:
        dialeto = csv.Sniffer().sniff(amostra, delimiters=",;")
    except csv.Error:
        dialeto = csv.excel
    leitor = csv.reader(io.StringIO(texto), dialeto)
    cabecalho = _normalizar_cabecalho_lista(next(leitor, []))
    _validar_cabecalho(cabecalho)
    for n, linha in enumerate(leitor, start=2):
        if not any(c.strip() for c in linha):
            continue
        yield n, dict(zip(cabecalho, linha))


def _iterar_xlsx(conteudo: bytes) -> Iterator[tuple[int, dict]]:
    try:
        # read_only + data_only: não carrega tudo em memória e não avalia fórmulas
        wb = load_workbook(io.BytesIO(conteudo), read_only=True, data_only=True)
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Planilha XLSX inválida ou corrompida.")
    try:
        linhas = wb.active.iter_rows(values_only=True)
        cabecalho = _normalizar_cabecalho_lista(next(linhas, []))
        _validar_cabecalho(cabecalho)
        for n, linha in enumerate(linhas, start=2):
            if not any(c not in (None, "") for c in linha):
                continue
            yield n, {k: ("" if v is None else str(v)) for k, v in zip(cabecalho, linha)}
    finally:
        wb.close()


def _normalizar_cabecalho_lista(cabecalho) -> list[str]:
    return [_normalizar_cabecalho(c) for c in cabecalho]


def _validar_cabecalho(cabecalho: list[str]) -> None:
    faltando = COLUNAS_OBRIGATORIAS - set(cabecalho)
    if faltando:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Colunas obrigatórias ausentes: {', '.join(sorted(faltando))}.",
        )


# ----------------------------------------------------------------------------
# Rota
# ----------------------------------------------------------------------------
@router.post("/importacao", response_model=ResumoImportacao)
def importar_clientes(
    arquivo: UploadFile = File(...),
    db: Session = Depends(get_db),
    usuario=Depends(get_current_user),
):
    # 1) Autorização
    if "clientes:importar" not in usuario.permissoes:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Sem permissão para importar clientes.")

    # 2) Tenant SEMPRE derivado do usuário autenticado
    empresa_id = usuario.empresa_id

    # 3) Validação do arquivo (antes de qualquer lock/consulta cara)
    nome_arquivo = (arquivo.filename or "").lower()
    ext = nome_arquivo[nome_arquivo.rfind("."):] if "." in nome_arquivo else ""
    if ext not in EXTENSOES_PERMITIDAS:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Envie um arquivo .csv ou .xlsx.")
    conteudo = _ler_upload(arquivo)
    iterador = _iterar_csv(conteudo) if ext == ".csv" else _iterar_xlsx(conteudo)

    # 4) Assinatura e limite do plano. O lock na linha da empresa serializa
    #    importações concorrentes e evita estourar o limite por condição de corrida.
    empresa = db.execute(
        select(Empresa).where(Empresa.id == empresa_id).with_for_update()
    ).scalar_one()
    if empresa.status_assinatura != "ativa":
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")
    plano = db.get(Plano, empresa.plano_id)

    atuais = db.scalar(
        select(func.count()).select_from(Cliente).where(Cliente.empresa_id == empresa_id)
    )
    # None = plano sem limite
    capacidade = None if plano.max_clientes is None else max(plano.max_clientes - atuais, 0)

    # 5) Processamento em lotes
    total = importados = duplicados = barrados_plano = com_erro = 0
    erros: list[ErroLinha] = []

    def registrar_erro(linha: int, motivo: str):
        nonlocal com_erro
        com_erro += 1
        if len(erros) < MAX_ERROS_NO_RESUMO:
            erros.append(ErroLinha(linha=linha, motivo=motivo))

    vistos_no_arquivo: set[str] = set()
    lote: list[tuple[int, LinhaCliente]] = []

    def processar_lote(itens: list[tuple[int, LinhaCliente]]):
        nonlocal importados, duplicados, barrados_plano, capacidade
        if not itens:
            return

        # Duplicados já existentes NESTA empresa (consulta sempre filtrada por tenant)
        docs = [d.documento for _, d in itens]
        existentes = set(
            db.scalars(
                select(Cliente.documento).where(
                    Cliente.empresa_id == empresa_id,
                    Cliente.documento.in_(docs),
                )
            )
        )

        novos: list[tuple[int, Cliente]] = []
        for linha, dados in itens:
            if dados.documento in existentes:
                duplicados += 1
                registrar_erro(linha, "documento já cadastrado")
                continue
            if capacidade is not None and capacidade <= 0:
                barrados_plano += 1
                registrar_erro(linha, "limite de clientes do plano atingido")
                continue
            novos.append((
                linha,
                Cliente(
                    empresa_id=empresa_id,                 # nunca vem da planilha
                    nome=dados.nome,
                    documento=dados.documento,
                    email=dados.email,
                    telefone=dados.telefone,
                    criado_por=usuario.id,
                ),
            ))
            if capacidade is not None:
                capacidade -= 1

        if not novos:
            return

        # Tenta inserir o lote inteiro em um SAVEPOINT; se falhar (ex.: corrida
        # na constraint única), cai para linha a linha para isolar o culpado.
        try:
            with db.begin_nested():
                db.add_all([c for _, c in novos])
                db.flush()
            importados += len(novos)
        except IntegrityError:
            for linha, cliente in novos:
                try:
                    with db.begin_nested():
                        db.add(Cliente(
                            empresa_id=empresa_id, nome=cliente.nome,
                            documento=cliente.documento, email=cliente.email,
                            telefone=cliente.telefone, criado_por=usuario.id,
                        ))
                        db.flush()
                    importados += 1
                except IntegrityError:
                    duplicados += 1
                    registrar_erro(linha, "documento já cadastrado")
                    if capacidade is not None:
                        capacidade += 1  # devolve a vaga não utilizada

    try:
        for numero_linha, bruto in iterador:
            total += 1
            if total > MAX_LINHAS:
                db.rollback()
                raise HTTPException(
                    status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    f"A planilha excede {MAX_LINHAS} linhas. Divida o arquivo.",
                )

            # Allowlist de colunas: ignora qualquer coluna extra (ex.: empresa_id, id, is_admin)
            filtrado = {k: v for k, v in bruto.items() if k in COLUNAS_ACEITAS}
            try:
                dados = LinhaCliente(**filtrado)
            except ValidationError as e:
                motivo = "; ".join(
                    f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors()
                )
                registrar_erro(numero_linha, motivo)
                continue

            if dados.documento in vistos_no_arquivo:
                duplicados += 1
                registrar_erro(numero_linha, "documento repetido na própria planilha")
                continue
            vistos_no_arquivo.add(dados.documento)

            lote.append((numero_linha, dados))
            if len(lote) >= TAMANHO_LOTE:
                processar_lote(lote)
                lote = []
        processar_lote(lote)

        db.commit()  # libera o lock da empresa
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        logger.exception("Falha na importação de clientes (empresa_id=%s)", empresa_id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Erro ao processar a importação.")

    # Log de auditoria sem dados pessoais
    logger.info(
        "importacao_clientes empresa_id=%s usuario_id=%s total=%s importados=%s duplicados=%s erros=%s",
        empresa_id, usuario.id, total, importados, duplicados, com_erro,
    )

    return ResumoImportacao(
        total_linhas=total,
        importados=importados,
        duplicados=duplicados,
        rejeitados_por_limite_do_plano=barrados_plano,
        com_erro=com_erro,
        erros=erros,
        erros_truncados=com_erro > len(erros),
    )