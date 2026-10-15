"""
app/routers/clientes_export.py

Exporta os dados cadastrais dos clientes da empresa do usuário autenticado
para uma planilha .xlsx.

Premissas (adapte aos módulos reais do projeto):
  - app.auth.get_current_user  -> retorna o usuário autenticado (com empresa_id,
                                  permissões e plano da empresa)
  - app.db.get_db              -> sessão SQLAlchemy síncrona
  - app.models                 -> Cliente, LogAuditoria
"""
import logging
import re
from datetime import date, datetime
from tempfile import SpooledTemporaryFile
from typing import Any, Iterator

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from openpyxl import Workbook
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.db import get_db
from app.models import Cliente, LogAuditoria

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/clientes", tags=["clientes"])

XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

# Limite por exportação: protege memória/CPU e respeita o máximo do Excel
# (1.048.576 linhas). Ajuste conforme o plano, se necessário.
MAX_LINHAS_EXPORTACAO = 100_000
TAMANHO_LOTE = 1_000

PERMISSAO_EXPORTAR = "clientes:exportar"
RECURSO_PLANO_EXPORTACAO = "exportacao_dados"

# Allowlist explícita de colunas: campos internos (ex.: empresa_id, hashes,
# notas internas) nunca são exportados por acidente.
COLUNAS = [
    ("Código", "id"),
    ("Nome / Razão social", "nome"),
    ("CPF/CNPJ", "documento"),
    ("E-mail", "email"),
    ("Telefone", "telefone"),
    ("Endereço", "endereco"),
    ("Cidade", "cidade"),
    ("UF", "uf"),
    ("CEP", "cep"),
    ("Cadastrado em", "criado_em"),
]

_PREFIXOS_FORMULA = ("=", "+", "-", "@", "\t", "\r")
_CARACTERES_ILEGAIS_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _sanitizar_celula(valor: Any) -> Any:
    """Converte o valor para algo seguro de gravar na planilha.

    - Neutraliza CSV/Formula Injection (texto iniciado por = + - @ vira texto).
    - Remove caracteres de controle que corrompem o XML do XLSX.
    - Remove timezone de datas (openpyxl não aceita datetimes tz-aware).
    """
    if valor is None:
        return ""
    if isinstance(valor, datetime):
        return valor.replace(tzinfo=None)
    if isinstance(valor, (int, float, date)):
        return valor
    texto = _CARACTERES_ILEGAIS_XML.sub("", str(valor))
    if texto.startswith(_PREFIXOS_FORMULA):
        texto = "'" + texto
    return texto


def _linhas(db: Session, empresa_id: int) -> Iterator[list[Any]]:
    """Lê os clientes em lotes, sempre filtrando pela empresa do usuário."""
    stmt = (
        select(Cliente)
        .where(Cliente.empresa_id == empresa_id)  # isolamento de tenant
        .where(Cliente.excluido_em.is_(None))  # ignora exclusões lógicas
        .order_by(Cliente.id)
        .limit(MAX_LINHAS_EXPORTACAO)
        .execution_options(yield_per=TAMANHO_LOTE)
    )
    for cliente in db.scalars(stmt):
        yield [_sanitizar_celula(getattr(cliente, attr, None)) for _, attr in COLUNAS]


def _gerar_xlsx(db: Session, empresa_id: int) -> tuple[SpooledTemporaryFile, int]:
    """Gera o XLSX em modo write_only (memória constante) num arquivo temporário."""
    wb = Workbook(write_only=True)
    ws = wb.create_sheet("Clientes")
    ws.append([titulo for titulo, _ in COLUNAS])

    total = 0
    for linha in _linhas(db, empresa_id):
        ws.append(linha)
        total += 1

    # Mantém até 10 MB em memória; acima disso, usa disco automaticamente.
    tmp = SpooledTemporaryFile(max_size=10 * 1024 * 1024)
    wb.save(tmp)
    tmp.seek(0)
    return tmp, total


def _iterar_arquivo(arquivo: SpooledTemporaryFile, chunk: int = 64 * 1024):
    try:
        while bloco := arquivo.read(chunk):
            yield bloco
    finally:
        arquivo.close()  # apaga o temporário


@router.get(
    "/exportar",
    summary="Exporta os clientes da empresa para XLSX",
    response_class=StreamingResponse,
    responses={200: {"content": {XLSX_MIME: {}}}},
)
def exportar_clientes(
    request: Request,
    db: Session = Depends(get_db),
    usuario=Depends(get_current_user),
):
    # 1) Autorização: o usuário pode exportar dados?
    if PERMISSAO_EXPORTAR not in usuario.permissoes:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Sem permissão para exportar clientes.")

    # 2) Plano de assinatura: o plano da empresa inclui exportação?
    if not usuario.empresa.plano_ativo or RECURSO_PLANO_EXPORTACAO not in usuario.empresa.plano.recursos:
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            "O plano atual da empresa não inclui exportação de dados.",
        )

    # 3) O tenant vem SEMPRE da sessão autenticada, nunca de parâmetro da requisição.
    empresa_id = usuario.empresa_id

    try:
        arquivo, total = _gerar_xlsx(db, empresa_id)
    except Exception:
        logger.exception("Falha ao exportar clientes (empresa_id=%s)", empresa_id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Não foi possível gerar a planilha.")

    # 4) Auditoria: exportação em massa de dados pessoais (LGPD) deve ser rastreável.
    db.add(
        LogAuditoria(
            empresa_id=empresa_id,
            usuario_id=usuario.id,
            acao="CLIENTES_EXPORTADOS",
            detalhes={"linhas": total, "formato": "xlsx"},
            ip=request.client.host if request.client else None,
        )
    )
    db.commit()

    # Nome do arquivo gerado pelo servidor (sem entrada do usuário -> sem header injection).
    nome_arquivo = f"clientes_{date.today():%Y%m%d}.xlsx"
    headers = {
        "Content-Disposition": f'attachment; filename="{nome_arquivo}"',
        "Cache-Control": "no-store",  # dados pessoais não devem ficar em cache
        "X-Content-Type-Options": "nosniff",
    }
    return StreamingResponse(_iterar_arquivo(arquivo), media_type=XLSX_MIME, headers=headers)