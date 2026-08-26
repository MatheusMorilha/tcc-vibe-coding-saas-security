# TCC — Vibe Coding & SaaS Security

Repositório de execução do experimento: geração de código por assistentes de IA e análise estática (SAST) comparativa entre braço **principal** e braço de **controle**.

> **Regra de ouro:** todos os comandos são executados a partir da **raiz do repositório** (`tcc-vibe-coding-saas-security`).

**Stack atual:** Semgrep + Snyk Code — SonarQube temporariamente fora do escopo.

---

## Estrutura do repositório

```
tcc-vibe-coding-saas-security/
├── amostras/
│   ├── principal/          P01 … P30
│   │   └── P01/
│   │       ├── P01_CHATGPT_PY_R1.py      (18 arquivos de código)
│   │       ├── …
│   │       ├── resultado_semgrep.json    (gerado no Passo 2)
│   │       ├── resultado_snyk.json       (gerado no Passo 2)
│   │       └── matriz_rastreabilidade_P01.xlsx  (gerado no Passo 3)
│   └── controle/           K01 … K10
├── prompts/                P01.md, P02.md, … K01.md, …
├── scripts/
│   ├── gerar_estrutura.py
│   ├── executar_sast_lote.py
│   ├── extrator_sast.py
│   └── verificar_seguros.py
└── README.md
```

### ⚠️ Prefixo do braço de controle: `K`, não `C`

Os scripts usam **`K01`–`K10`** para o controle:

- `gerar_estrutura.py` cria as pastas com o prefixo `K`;
- `extrator_sast.py` classifica como *Controle* apenas arquivos cujo cenário começa com `K` (`P` → Principal, `K` → Controle, qualquer outro → **Desconhecido**).

Se o texto do TCC usa `C01`–`C10`, é preciso escolher um dos dois e padronizar: ou renomear as pastas/arquivos para `C` **e** ajustar o `parse_nome_arquivo`, ou manter `K` no repositório e alinhar a redação. Misturar os dois faz o extrator marcar o braço como *Desconhecido*.

### Convenção de nomes

```
<CENARIO>_<ASSISTENTE>_<LINGUAGEM>_R<n>.<ext>
```

Exemplo: `amostras/principal/P01/P01_CHATGPT_PY_R1.py`

| Campo | Valores aceitos |
|---|---|
| `CENARIO` | `P01`–`P30` (principal), `K01`–`K10` (controle) |
| `ASSISTENTE` | `CHATGPT`, `CLAUDE`, `COPILOT` |
| `LINGUAGEM` | `PY` (`.py`), `NODE` (`.js`) |
| `R<n>` | `R1`, `R2`, `R3` |

> **Exatamente 4 blocos separados por `_`.** O extrator faz `split('_')` e descarta qualquer arquivo que não tenha 4 partes. Um nome como `P01_CLAUDE_PY_R1_v2.py` **não entra na matriz** — o achado some silenciosamente, sem mensagem de erro.

**Total por cenário:** 3 assistentes × 2 linguagens × 3 repetições = **18 arquivos**.

---

## Fluxo completo

```
[0] Gerar estrutura → [1] Gerar códigos com as IAs → [2] Varredura SAST → [3] Extrair matriz → [4] Conferir amostras limpas
```

---

## Passo 0 — Gerar a estrutura de pastas (uma vez)

```bash
python3 scripts/gerar_estrutura.py
```

Cria `amostras/principal/P01…P30` e `amostras/controle/K01…K10`, cada uma com os 18 arquivos vazios já nomeados.

É **idempotente**: arquivos existentes nunca são sobrescritos. O terminal informa quantos foram criados e quantos foram preservados — pode rodar de novo sem medo se precisar recriar algo que foi apagado.

---

## Passo 1 — Gerar e inserir o código (manual)

Popular os **18 arquivos** da pasta do cenário (ex.: `amostras/principal/P01/`).

| # | Ação |
|---|------|
| 1 | Copiar o prompt exato de `prompts/P01.md` |
| 2 | Abrir a IA (ChatGPT / Claude / Copilot) |
| 3 | **Abrir um chat NOVO a cada repetição (R1, R2, R3)** |
| 4 | Colar **apenas o bloco de código** no arquivo correspondente |
| 5 | Repetir até os 18 arquivos estarem preenchidos |

### ⚠️ Controle de *history bias*

Cada repetição **exige uma conversa nova**. A IA não pode ter em contexto o código que gerou na repetição anterior — isso contamina a independência das amostras.

### ⚠️ Dependências geradas pela IA

**Nunca instalar** pacotes sugeridos pelo código gerado (risco de *package hallucination*). A análise é estática; nada precisa executar.

**Checklist antes de seguir:** 18/18 arquivos preenchidos, nenhum vazio, nenhum com texto explicativo da IA junto do código, nenhum nome fora da convenção.

---

## Passo 2 — Varredura SAST (batch)

```bash
python3 scripts/executar_sast_lote.py amostras/principal/P01
```

- Roda **Semgrep** (`semgrep scan --quiet --exclude="*.json" --json`) e depois **Snyk Code** (`snyk code test --json`) sobre a pasta inteira.
- Relatórios brutos gravados **dentro da pasta do cenário**: `resultado_semgrep.json` e `resultado_snyk.json`.
- **Saída esperada:** `Varredura concluída com sucesso para amostras/principal/P01!`

**Observações operacionais**

- O `--exclude="*.json"` impede que o Semgrep analise os próprios relatórios. Mantenha essa flag.
- `snyk code test` termina com **código de saída ≠ 0 quando encontra achados**. Isso é comportamento normal da ferramenta, não falha do script.
- Se o JSON do Snyk sair vazio ou sem a chave `runs`, o extrator simplesmente não contabiliza achados dessa ferramenta — vale conferir se o login (`snyk auth`) ainda está válido antes de concluir que o lote é limpo.

---

## Passo 3 — Extração da matriz de rastreabilidade

```bash
python3 scripts/extrator_sast.py amostras/principal/P01
```

Converte os JSONs brutos em dado científico: metadados do experimento + classificação **OWASP** + normalização de severidade. Achados duplicados (mesmo `Arquivo` + `Linha` + `ID CWE`) são removidos, mantendo o primeiro.

Gera `matriz_rastreabilidade_P01.xlsx` na própria pasta do cenário, com as colunas:

`Cenário` · `Braço Experimental` · `Assistente` · `Linguagem` · `Repetição` · `Arquivo` · `Ferramenta` · `Linha` · `ID CWE` · `Categoria OWASP 2025` · `Severidade Normalizada` · `Desfecho Triagem`

> A coluna **`Desfecho Triagem`** sai vazia de propósito: é o campo preenchido à mão na triagem cega.

### Dois resultados possíveis

| Terminal diz | Significado | O que fazer |
|---|---|---|
| `Sucesso! Matriz exportada` | Vulnerabilidades detectadas | Abrir o `.xlsx` e seguir para a triagem humana |
| `Nenhum dado encontrado ou arquivos JSON ausentes/vazios.` | **Não é erro.** Taxa de 0% de vulnerabilidades naquele lote | Registrar o resultado nulo no TCC e seguir para o próximo cenário |

> Resultado nulo é dado válido. Ele sustenta a análise comparativa entre cenários — não descarte.

### Normalização de severidade

| Ferramenta | Original | Normalizada |
|---|---|---|
| Semgrep | `ERROR` / `HIGH` | Alta |
| Semgrep | `WARNING` / `MEDIUM` | Média |
| Semgrep | `INFO` / `LOW` | Baixa |
| Snyk Code | `error` | Alta |
| Snyk Code | `warning` | Média |
| Snyk Code | `note` | Baixa |

Qualquer valor fora dessa tabela vira `Não Classificada` — se aparecer na matriz, é sinal de que o mapeamento precisa ser estendido.

### Mapeamento OWASP

O dicionário `MAPEAMENTO_OWASP` (topo do `extrator_sast.py`) cobre hoje CWEs de Injection, Broken Access Control, Authentication Failures e Security Misconfiguration, além de algumas regras nativas do Snyk (`python/Sqli`, `python/HardcodedNonCryptoSecret`, `python/RunWithDebugTrue`).

O que não estiver no dicionário cai em **`Outro / Não Mapeado`**. Essa categoria deve ser revisada a cada cenário: ou o achado é irrelevante, ou o dicionário precisa de mais uma entrada. Toda alteração no mapeamento **exige reprocessar os cenários já extraídos** para manter a comparabilidade.

---

## Passo 4 — Conferir as amostras limpas

```bash
python3 scripts/verificar_seguros.py amostras/principal/P01
```

Cruza os arquivos `.py`/`.js` presentes na pasta com a coluna `Arquivo` da matriz. O que não aparece na matriz é amostra sem achado de SAST.

Relatório no terminal: total de amostras, quantas vulneráveis, quantas limpas e a lista nominal das limpas.

> Se o total de amostras vier diferente de **18**, algo ficou faltando no Passo 1 — confira antes de registrar o cenário como concluído.

---

## Guardas de segurança (idempotência)

Todos os scripts se recusam a sobrescrever trabalho já feito:

| Script | Aborta quando | Como reprocessar de propósito |
|---|---|---|
| `gerar_estrutura.py` | Nunca aborta; apenas preserva arquivos existentes | — |
| `executar_sast_lote.py` | Já existe `resultado_semgrep.json` **ou** `resultado_snyk.json` | Apagar os dois JSONs da pasta do cenário |
| `extrator_sast.py` | Já existe `matriz_rastreabilidade_<CENARIO>.xlsx` | Mover/renomear o `.xlsx` — **nunca apagar sem backup**, ele pode conter triagem manual |

Isso protege a triagem cega contra reexecuções acidentais. Apagar um `.xlsx` já triado significa refazer a triagem daquele cenário do zero.

---

## Reprodutibilidade

Registrar e manter fixos, no caderno de bordo do TCC:

- versão do Semgrep e do conjunto de regras (*ruleset* congelado);
- versão do CLI do Snyk;
- data de execução de cada lote;
- versão do Python e do `pandas`.

Mudança de versão de ferramenta no meio da coleta invalida a comparação entre cenários coletados antes e depois.

---

## Rotina resumida (por cenário)

Substitua `P01` pelo cenário da vez:

```bash
# 1. Gerar e colar os 18 códigos no VS Code (chat novo por repetição)

# 2. Varredura
python3 scripts/executar_sast_lote.py amostras/principal/P01

# 3. Extração
python3 scripts/extrator_sast.py amostras/principal/P01

# 4. Conferência das amostras limpas
python3 scripts/verificar_seguros.py amostras/principal/P01

# 5. Próximo cenário → P02, P03, ...
```

Cenários de controle seguem o mesmo fluxo, trocando o caminho:

```bash
python3 scripts/executar_sast_lote.py amostras/controle/K01
python3 scripts/extrator_sast.py amostras/controle/K01
python3 scripts/verificar_seguros.py amostras/controle/K01
```

---

## Versionamento

O `.gitignore` ignora caches (`__pycache__/`, `.venv/`, `.semgrep/`, `.snyk/`, `.scannerwork/`, `.sonar/`), logs e arquivos de sistema.

**Os relatórios `.json` e as matrizes `.xlsx` são versionados de propósito** — são a evidência bruta do experimento e precisam estar no histórico do repositório.

---

## Controle de progresso

| Lote | Cenários | Feito |
|---|---|---|
| Principal | P01 – P30 | ☐ |
| Controle | K01 – K10 | ☐ |

Após a extração de todos os cenários, o próximo estágio é a **triagem cega** e o cálculo do **kappa de Cohen** entre os avaliadores.