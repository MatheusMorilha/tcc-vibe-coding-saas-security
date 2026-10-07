diff --git a/README.md b/README.md
index 0e88df6..8d96aab 100644
--- a/README.md
+++ b/README.md
@@ -25,8 +25,9 @@ tcc-vibe-coding-saas-security/
 ├── scripts/
 │   ├── gerar_estrutura.py
 │   ├── executar_sast_lote.py
-│   ├── extrator_sast.py
-│   └── verificar_seguros.py
+│   └── extrator_sast.py
+├── docs/
+│   └── mapeamento_owasp_cwe_2025.md   (fonte do dicionário MAPEAMENTO_OWASP)
 └── README.md
 ```
 
@@ -63,7 +64,7 @@ Exemplo: `amostras/principal/P01/P01_CHATGPT_PY_R1.py`
 ## Fluxo completo
 
 ```
-[0] Gerar estrutura → [1] Gerar códigos com as IAs → [2] Varredura SAST → [3] Extrair matriz → [4] Conferir amostras limpas
+[0] Gerar estrutura → [1] Gerar códigos com as IAs → [2] Varredura SAST → [3] Extrair matriz
 ```
 
 ---
@@ -112,13 +113,14 @@ python3 scripts/executar_sast_lote.py amostras/principal/P01
 
 - Roda **Semgrep** (`semgrep scan --quiet --exclude="*.json" --json`) e depois **Snyk Code** (`snyk code test --json`) sobre a pasta inteira.
 - Relatórios brutos gravados **dentro da pasta do cenário**: `resultado_semgrep.json` e `resultado_snyk.json`.
-- **Saída esperada:** `Varredura concluída com sucesso para amostras/principal/P01!`
+- O script valida o resultado de cada ferramenta antes de declarar sucesso: código de saída, JSON não-vazio, JSON parseável e presença da chave esperada (`results` no Semgrep, `runs` não-vazio no Snyk).
+- **Saída esperada em caso de sucesso:** `✅ Semgrep concluído.` / `✅ Snyk Code concluído.` seguido de `Varredura concluída com sucesso para amostras/principal/P01!`
+- **Em caso de falha:** o script imprime `❌` com o motivo específico (ex.: sessão do Snyk expirada, JSON inválido) e encerra com código de saída 1, sem marcar o cenário como concluído. Apague o(s) JSON(s) inválido(s) da pasta e rode de novo depois de corrigir.
 
 **Observações operacionais**
 
 - O `--exclude="*.json"` impede que o Semgrep analise os próprios relatórios. Mantenha essa flag.
-- `snyk code test` termina com **código de saída ≠ 0 quando encontra achados**. Isso é comportamento normal da ferramenta, não falha do script.
-- Se o JSON do Snyk sair vazio ou sem a chave `runs`, o extrator simplesmente não contabiliza achados dessa ferramenta — vale conferir se o login (`snyk auth`) ainda está válido antes de concluir que o lote é limpo.
+- `snyk code test` termina com **código de saída ≠ 0 quando encontra achados**. Isso é comportamento normal da ferramenta, não falha do script (só os códigos `2` e `3` são tratados como falha real).
 
 ---
 
@@ -160,26 +162,12 @@ Qualquer valor fora dessa tabela vira `Não Classificada` — se aparecer na mat
 
 ### Mapeamento OWASP
 
-O dicionário `MAPEAMENTO_OWASP` (topo do `extrator_sast.py`) cobre hoje CWEs de Injection, Broken Access Control, Authentication Failures e Security Misconfiguration, além de algumas regras nativas do Snyk (`python/Sqli`, `python/HardcodedNonCryptoSecret`, `python/RunWithDebugTrue`).
+O dicionário `MAPEAMENTO_OWASP` (topo do `extrator_sast.py`) cobre as 10 categorias do OWASP Top 10:2025 (A01–A10), incluindo a A10 (Mishandling of Exceptional Conditions), além de algumas regras nativas do Snyk resolvidas via CWE declarado pela própria regra. A fonte completa (249 CWEs, com descrição e links das páginas oficiais consultadas) está documentada em `docs/mapeamento_owasp_cwe_2025.md`.
 
 O que não estiver no dicionário cai em **`Outro / Não Mapeado`**. Essa categoria deve ser revisada a cada cenário: ou o achado é irrelevante, ou o dicionário precisa de mais uma entrada. Toda alteração no mapeamento **exige reprocessar os cenários já extraídos** para manter a comparabilidade.
 
 ---
 
-## Passo 4 — Conferir as amostras limpas
-
-```bash
-python3 scripts/verificar_seguros.py amostras/principal/P01
-```
-
-Cruza os arquivos `.py`/`.js` presentes na pasta com a coluna `Arquivo` da matriz. O que não aparece na matriz é amostra sem achado de SAST.
-
-Relatório no terminal: total de amostras, quantas vulneráveis, quantas limpas e a lista nominal das limpas.
-
-> Se o total de amostras vier diferente de **18**, algo ficou faltando no Passo 1 — confira antes de registrar o cenário como concluído.
-
----
-
 ## Guardas de segurança (idempotência)
 
 Todos os scripts se recusam a sobrescrever trabalho já feito:
@@ -220,10 +208,7 @@ python3 scripts/executar_sast_lote.py amostras/principal/P01
 # 3. Extração
 python3 scripts/extrator_sast.py amostras/principal/P01
 
-# 4. Conferência das amostras limpas
-python3 scripts/verificar_seguros.py amostras/principal/P01
-
-# 5. Próximo cenário → P02, P03, ...
+# 4. Próximo cenário → P02, P03, ...
 ```
 
 Cenários de controle seguem o mesmo fluxo, trocando o caminho:
@@ -231,7 +216,6 @@ Cenários de controle seguem o mesmo fluxo, trocando o caminho:
 ```bash
 python3 scripts/executar_sast_lote.py amostras/controle/K01
 python3 scripts/extrator_sast.py amostras/controle/K01
-python3 scripts/verificar_seguros.py amostras/controle/K01
 ```
 
 ---