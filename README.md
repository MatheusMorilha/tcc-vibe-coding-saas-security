# Guia de Execução de Cenários — TCC Vibe Coding SaaS Security

> **Regra de ouro:** todos os comandos são executados a partir da **raiz do repositório** (`tcc-vibe-coding-saas-security`).

Stack atual: **Semgrep + Snyk Code** (SonarQube temporariamente fora do escopo).

---

## Fluxo em 3 passos

```
[1] Gerar códigos com as IAs  →  [2] Varredura SAST  →  [3] Extrair matriz (.xlsx)
```

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

### Convenção de nomes
```
P01_<IA>_<LINGUAGEM>_R<n>.<ext>
```
Exemplo: `amostras/principal/P01/P01_CHATGPT_PY_R1.py`

**Checklist antes de seguir:** 18/18 arquivos preenchidos, nenhum vazio, nenhum com texto explicativo da IA junto do código.

---

## Passo 2 — Varredura SAST (batch)

```bash
python3 scripts/executar_sast_lote.py amostras/principal/P01
```

- O script lê os 18 códigos da pasta informada e grava os relatórios brutos **dentro dela**.
- **Saída esperada no terminal:** progresso do Semgrep e do Snyk → `Varredura concluída com sucesso para amostras/principal/P01!`
- **Arquivos gerados:** `resultado_semgrep.json` e `resultado_snyk.json`

---

## Passo 3 — Extração da matriz de rastreabilidade

```bash
python3 scripts/extrator_sast.py amostras/principal/P01
```

Converte os JSONs brutos em dado científico: classificação **OWASP Top 10** + normalização de severidade.

### Dois resultados possíveis

| Terminal diz | Significado | O que fazer |
|---|---|---|
| `Sucesso! Matriz exportada` | Vulnerabilidades detectadas | Abrir `amostras/principal/P01/matriz_rastreabilidade_P01.xlsx` e seguir para a triagem humana |
| `Nenhum dado encontrado ou arquivos JSON ausentes/vazios.` | **Não é erro.** Taxa de 0% de vulnerabilidades naquele lote | Registrar o resultado nulo no TCC e seguir para o próximo cenário |

> Resultado nulo é dado válido. Ele sustenta a análise comparativa entre cenários — não descarte.

---

## Rotina resumida (por cenário)

Substitua `P01` pelo cenário da vez:

```bash
# 1. Gerar e colar os 18 códigos no VS Code (chat novo por repetição)

# 2. Varredura
python3 scripts/executar_sast_lote.py amostras/principal/P01

# 3. Extração
python3 scripts/extrator_sast.py amostras/principal/P01

# 4. Próximo cenário → P02, P03, ...
```

Cenários de controle seguem o mesmo fluxo, trocando o caminho:

```bash
python3 scripts/executar_sast_lote.py amostras/controle/C01
python3 scripts/extrator_sast.py amostras/controle/C01
```

---

## Controle de progresso

| Lote | Cenários | Feito |
|---|---|---|
| Principal | P01 – P30 | ☐ |
| Controle | C01 – C10 | ☐ |

Após a extração de todos os cenários, o próximo estágio é a **triagem cega** e o cálculo do **kappa de Cohen** entre os avaliadores.