import os
import sys
import json
import pandas as pd

# ==============================================================================
# 1. REGRAS DE NEGÓCIO E MAPEAMENTO (OWASP TOP 10: 2025)
# ==============================================================================

# Agrupamento das vulnerabilidades baseado na lista oficial OWASP Top 10: 2025
OWASP_2025_CATEGORIES = {
    "A01:2025 - Broken Access Control": [
        "CWE-22", "CWE-23", "CWE-36", "CWE-59", "CWE-61", "CWE-65", "CWE-200", 
        "CWE-201", "CWE-219", "CWE-276", "CWE-281", "CWE-282", "CWE-283", "CWE-284", 
        "CWE-285", "CWE-352", "CWE-359", "CWE-377", "CWE-379", "CWE-402", "CWE-424", 
        "CWE-425", "CWE-441", "CWE-497", "CWE-538", "CWE-540", "CWE-548", "CWE-552", 
        "CWE-566", "CWE-601", "CWE-615", "CWE-639", "CWE-668", "CWE-732", "CWE-749", 
        "CWE-862", "CWE-863", "CWE-918", "CWE-922", "CWE-1275"
    ],
    "A02:2025 - Security Misconfiguration": [
        "CWE-5", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315", 
        "CWE-489", "CWE-526", "CWE-547", "CWE-611", "CWE-614", "CWE-776", "CWE-942",
        "CWE-1004", "CWE-1174"
    ],
    "A03:2025 - Software Supply Chain Failures": [
        "CWE-447", "CWE-1035", "CWE-1104", "CWE-1329", "CWE-1357", "CWE-1395"
    ],
    "A04:2025 - Cryptographic Failures": [
        "CWE-261", "CWE-296", "CWE-319", "CWE-320", "CWE-321", "CWE-322", "CWE-323", 
        "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330", 
        "CWE-331", "CWE-332", "CWE-334", "CWE-335", "CWE-336", "CWE-337", "CWE-338", 
        "CWE-340", "CWE-342", "CWE-347", "CWE-523", "CWE-757", "CWE-759", "CWE-760", 
        "CWE-780", "CWE-916", "CWE-1240", "CWE-1241"
    ],
    "A05:2025 - Injection": [
        "CWE-20", "CWE-74", "CWE-76", "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-83", 
        "CWE-86", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-94", "CWE-95", 
        "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-103", "CWE-104", "CWE-112", 
        "CWE-113", "CWE-114", "CWE-115", "CWE-116", "CWE-129", "CWE-159", "CWE-470", 
        "CWE-493", "CWE-500", "CWE-564", "CWE-610", "CWE-643", "CWE-644", "CWE-917"
    ],
    "A06:2025 - Insecure Design": [
        "CWE-73", "CWE-183", "CWE-256", "CWE-266", "CWE-269", "CWE-286", "CWE-311", 
        "CWE-312", "CWE-313", "CWE-316", "CWE-362", "CWE-382", "CWE-419", "CWE-434", 
        "CWE-436", "CWE-444", "CWE-451", "CWE-454", "CWE-472", "CWE-501", "CWE-522", 
        "CWE-525", "CWE-539", "CWE-598", "CWE-602", "CWE-628", "CWE-642", "CWE-646", 
        "CWE-653", "CWE-656", "CWE-657", "CWE-676", "CWE-693", "CWE-799", "CWE-807", 
        "CWE-841", "CWE-1021", "CWE-1022", "CWE-1125"
    ],
    "A07:2025 - Authentication Failures": [
        "CWE-258", "CWE-259", "CWE-287", "CWE-288", "CWE-289", "CWE-290", "CWE-291", 
        "CWE-293", "CWE-294", "CWE-295", "CWE-297", "CWE-298", "CWE-299", "CWE-300", 
        "CWE-302", "CWE-303", "CWE-304", "CWE-305", "CWE-306", "CWE-307", "CWE-308", 
        "CWE-309", "CWE-346", "CWE-350", "CWE-384", "CWE-521", "CWE-613", "CWE-620", 
        "CWE-640", "CWE-798", "CWE-940", "CWE-941", "CWE-1390", "CWE-1391", "CWE-1392",
        "CWE-1393"
    ],
    "A08:2025 - Software or Data Integrity Failures": [
        "CWE-345", "CWE-353", "CWE-426", "CWE-427", "CWE-494", "CWE-502", "CWE-506", 
        "CWE-509", "CWE-565", "CWE-784", "CWE-829", "CWE-830", "CWE-915", "CWE-926"
    ],
    "A09:2025 - Security Logging and Alerting Failures": [
        "CWE-117", "CWE-221", "CWE-223", "CWE-532", "CWE-778"
    ],
    "A10:2025 - Mishandling of Exceptional Conditions": [
        "CWE-209", "CWE-215", "CWE-234", "CWE-235", "CWE-248", "CWE-252", "CWE-274", 
        "CWE-280", "CWE-369", "CWE-390", "CWE-391", "CWE-394", "CWE-396", "CWE-397", 
        "CWE-460", "CWE-476", "CWE-478", "CWE-484", "CWE-550", "CWE-636", "CWE-703", 
        "CWE-754", "CWE-755", "CWE-756"
    ]
}

# Constrói o dicionário de mapeamento invertido para busca O(1)
MAPEAMENTO_OWASP = {}
for categoria, cwes in OWASP_2025_CATEGORIES.items():
    for cwe in cwes:
        MAPEAMENTO_OWASP[cwe] = categoria

def limpar_cwe(cwe_bruto):
    # Reduz "CWE-704: Incorrect Type Conversion or Cast" a apenas "CWE-704"
    return str(cwe_bruto).split(':')[0].strip()

def obter_categoria_owasp(id_regra):
    # Procura a regra exata, senão procura o prefixo CWE
    regra_limpa = limpar_cwe(id_regra)
    return MAPEAMENTO_OWASP.get(regra_limpa, MAPEAMENTO_OWASP.get(id_regra, "Outro / Não Mapeado"))

def extrair_categoria_2025_do_owasp(campo_owasp):
    # O Semgrep já entrega, em alguns rulesets, o mapeamento OWASP pronto no
    # metadado da regra (extra.metadata.owasp). Quando existe uma entrada da
    # edição 2025, ela é mais confiável do que redescobrir a categoria a
    # partir do CWE isolado (regras diferentes podem taguear o mesmo tipo de
    # falha com CWEs distintos e não necessariamente o mais representativo).
    if not campo_owasp:
        return None
    itens = campo_owasp if isinstance(campo_owasp, list) else [campo_owasp]
    for item in itens:
        if "2025" in str(item):
            return str(item)
    return None

def normalizar_severidade(ferramenta, severidade_original):
    sev = str(severidade_original).upper()
    if ferramenta == "Snyk Code":
        if sev == "ERROR": return "Alta"
        if sev == "WARNING": return "Média"
        if sev == "NOTE": return "Baixa"
    elif ferramenta == "Semgrep":
        if sev in ["ERROR", "HIGH"]: return "Alta"
        if sev in ["WARNING", "MEDIUM"]: return "Média"
        if sev in ["INFO", "LOW"]: return "Baixa"
    return "Não Classificada"

# Ordem de severidade usada para decidir qual prevalece quando duas
# ferramentas relatam o mesmo achado com severidades diferentes: fica a mais
# alta das duas, por segurança (nunca a triagem subestima o risco).
ORDEM_SEVERIDADE = {"Alta": 3, "Média": 2, "Baixa": 1, "Não Classificada": 0,
                     "Nenhuma": 0, "Não Aplicável": 0}

def combinar_severidade(valores):
    return max(valores, key=lambda s: ORDEM_SEVERIDADE.get(s, 0))

def combinar_categoria(valores):
    # Achados do mesmo CWE deveriam sempre cair na mesma categoria OWASP,
    # mas por segurança: se por algum motivo divergirem, prioriza qualquer
    # valor mapeado em vez de "Outro / Não Mapeado".
    valores = list(valores)
    for valor in valores:
        if valor != "Outro / Não Mapeado":
            return valor
    return valores[0]

def combinar_ferramentas(valores):
    # Registra todas as ferramentas que confirmaram o mesmo achado (mesmo
    # arquivo, linha e CWE), em vez de manter só a primeira e descartar a
    # informação de que a outra também encontrou o mesmo problema.
    return " + ".join(sorted(set(valores)))

# (Mantenha o restante do seu código a partir daqui)

def parse_nome_arquivo(nome_arquivo):
    base = os.path.basename(nome_arquivo)
    nome_sem_ext = os.path.splitext(base)[0]
    partes = nome_sem_ext.split('_')
    if len(partes) != 4: return None
    
    cenario, assistente, linguagem, repeticao = partes
    braco = "Principal" if cenario.upper().startswith("P") else "Controle" if cenario.upper().startswith("K") else "Desconhecido"
    
    return {
        "Braço Experimental": braco,
        "Cenário": cenario.upper(),
        "Assistente": assistente,
        "Linguagem": linguagem,
        "Repetição": repeticao,
        "Arquivo": base
    }

# ==============================================================================
# 2. EXTRAÇÃO DE DADOS DOS RELATÓRIOS
# ==============================================================================

def processar_semgrep(caminho_json):
    achados = []
    if not os.path.exists(caminho_json): return achados
    with open(caminho_json, 'r', encoding='utf-8') as f: dados = json.load(f)
    for issue in dados.get("results", []):
        arquivo = issue.get("path", "")
        metadados = parse_nome_arquivo(arquivo)
        if not metadados: continue
        metadata = issue.get("extra", {}).get("metadata", {})
        cwe_info = metadata.get("cwe", ["CWE-Desconhecido"])
        if isinstance(cwe_info, list) and len(cwe_info) > 0: cwe_info = cwe_info[0]
        cwe_limpo = limpar_cwe(cwe_info)

        # Prioriza a categoria OWASP 2025 que a própria regra já declara;
        # só reconstrói a partir do CWE quando a regra não informa isso.
        categoria = extrair_categoria_2025_do_owasp(metadata.get("owasp")) or obter_categoria_owasp(cwe_limpo)

        registro = {
            **metadados,
            "Ferramenta": "Semgrep",
            "Linha": issue.get("start", {}).get("line", 0),
            "ID CWE": cwe_limpo,
            "Categoria OWASP 2025": categoria,
            "Severidade Normalizada": normalizar_severidade("Semgrep", issue.get("extra", {}).get("severity", "")),
            "Desfecho Triagem": ""
        }
        achados.append(registro)
    return achados

def processar_snyk(caminho_json):
    achados = []
    if not os.path.exists(caminho_json): return achados
    with open(caminho_json, 'r', encoding='utf-8') as f: dados = json.load(f)
    runs = dados.get("runs", [])
    if not runs: return achados
    for run in runs:
        # O ruleId do Snyk (ex.: "python/Sqli") é um identificador interno da
        # ferramenta, não um CWE. O CWE real de cada regra vem separado, em
        # tool.driver.rules[].properties.cwe — monta-se aqui o mapa ruleId -> CWE
        # para não depender de patches manuais por ruleId no dicionário OWASP.
        mapa_regra_para_cwe = {}
        for regra in run.get("tool", {}).get("driver", {}).get("rules", []):
            cwes_da_regra = regra.get("properties", {}).get("cwe", [])
            if cwes_da_regra:
                mapa_regra_para_cwe[regra.get("id")] = limpar_cwe(cwes_da_regra[0])

        for result in run.get("results", []):
            locations = result.get("locations", [])
            if not locations: continue
            arquivo = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            metadados = parse_nome_arquivo(arquivo)
            if not metadados: continue

            rule_id = result.get("ruleId", "")
            cwe_real = mapa_regra_para_cwe.get(rule_id)
            id_cwe_final = cwe_real if cwe_real else rule_id
            categoria = obter_categoria_owasp(cwe_real) if cwe_real else "Outro / Não Mapeado"

            registro = {
                **metadados,
                "Ferramenta": "Snyk Code",
                "Linha": locations[0].get("physicalLocation", {}).get("region", {}).get("startLine", 0),
                "ID CWE": id_cwe_final,
                "Categoria OWASP 2025": categoria,
                "Severidade Normalizada": normalizar_severidade("Snyk Code", result.get("level", "note")),
                "Desfecho Triagem": ""
            }
            achados.append(registro)
    return achados

def listar_amostras_por_status(pasta_cenario):
    # Separa os .py/.js da pasta em preenchidos (já têm conteúdo) e vazios
    # (0 bytes, Passo 1 ainda pendente). Um arquivo vazio não é uma amostra
    # "sem vulnerabilidade" nem deve ser tratado como inexistente — é uma
    # amostra que ainda falta gerar. Mesma distinção usada em
    # verificar_seguros.py.
    preenchidas, vazias = [], []
    for nome in sorted(os.listdir(pasta_cenario)):
        if not nome.endswith(('.py', '.js')):
            continue
        caminho = os.path.join(pasta_cenario, nome)
        if os.path.getsize(caminho) == 0:
            vazias.append(nome)
        else:
            preenchidas.append(nome)
    return preenchidas, vazias

def consolidar_e_exportar(lote_pasta, nome_saida):
    # Define o nome e o caminho do arquivo final que será gerado
    caminho_excel = os.path.join(lote_pasta, f"matriz_rastreabilidade_{nome_saida}.xlsx")
    
    # ==================================================================
    # MEDIDA DE SEGURANÇA: Prevenir sobrescrita da Matriz (Protege a Triagem)
    # ==================================================================
    if os.path.exists(caminho_excel):
        print(f"\n⚠️ AVISO: A matriz para o cenário '{nome_saida}' já foi extraída!")
        print(f"O arquivo '{caminho_excel}' já existe nesta pasta.")
        print("Modo de segurança: Extração abortada para não sobrescrever dados ou triagens manuais.\n")
        return

    print(f"Iniciando consolidação do lote: {lote_pasta}...")

    # Define os caminhos dos relatórios
    semgrep_json = os.path.join(lote_pasta, "resultado_semgrep.json")
    snyk_json = os.path.join(lote_pasta, "resultado_snyk.json")

    if not os.path.exists(semgrep_json) and not os.path.exists(snyk_json):
        print("Nenhum relatório de SAST encontrado nesta pasta. Rode a Etapa 2 (executar_sast_lote.py) antes de extrair.")
        return

    dados_totais = processar_semgrep(semgrep_json) + processar_snyk(snyk_json)

    # Acrescenta uma linha para cada amostra já gerada que não teve nenhum
    # achado em nenhuma das ferramentas, para que toda amostra preenchida
    # apareça na matriz — inclusive as limpas — e os indicadores (% de
    # amostras limpas por assistente/linguagem/categoria etc.) possam ser
    # calculados direto da planilha, sem cruzar com a pasta de arquivos.
    preenchidas, vazias = listar_amostras_por_status(lote_pasta)

    arquivos_com_achado = {registro["Arquivo"] for registro in dados_totais}
    for arquivo in preenchidas:
        if arquivo in arquivos_com_achado:
            continue
        metadados = parse_nome_arquivo(arquivo)
        if not metadados:
            continue
        dados_totais.append({
            **metadados,
            "Ferramenta": "Nenhuma",
            "Linha": None,
            "ID CWE": "Nenhum",
            "Categoria OWASP 2025": "Nenhuma / Sem Achados",
            "Severidade Normalizada": "Nenhuma",
            "Desfecho Triagem": "Não se aplica (amostra limpa)"
        })

    # Acrescenta também uma linha para cada amostra ainda vazia, para que a
    # própria matriz mostre o andamento do Passo 1 (o que já foi gerado e o
    # que ainda falta), em vez de simplesmente omitir o arquivo.
    for arquivo in vazias:
        metadados = parse_nome_arquivo(arquivo)
        if not metadados:
            continue
        dados_totais.append({
            **metadados,
            "Ferramenta": "Não Aplicável",
            "Linha": None,
            "ID CWE": "Não Aplicável",
            "Categoria OWASP 2025": "Amostra Não Preenchida",
            "Severidade Normalizada": "Não Aplicável",
            "Desfecho Triagem": "Aguardando geração (Passo 1 pendente)"
        })

    if not dados_totais:
        print("Nenhum arquivo .py/.js encontrado nesta pasta. Nada para exportar.")
        return

    df = pd.DataFrame(dados_totais)

    # Quando Semgrep e Snyk Code relatam o mesmo achado (mesmo arquivo, linha
    # e CWE), as duas ocorrências são consolidadas numa única linha em vez de
    # a segunda ser simplesmente descartada — a coluna "Ferramenta" passa a
    # registrar todas as ferramentas que confirmaram aquele achado (ex.:
    # "Semgrep + Snyk Code"). Isso preserva o dado de concordância entre
    # motores, necessário para indicadores como "% de achados de severidade
    # alta confirmados por mais de uma ferramenta".
    chave_achado = ["Cenário", "Braço Experimental", "Assistente", "Linguagem",
                     "Repetição", "Arquivo", "Linha", "ID CWE"]
    df = df.groupby(chave_achado, dropna=False, as_index=False).agg({
        "Ferramenta": combinar_ferramentas,
        "Categoria OWASP 2025": combinar_categoria,
        "Severidade Normalizada": combinar_severidade,
        "Desfecho Triagem": "first",
    })

    colunas_ordem = [
        "Cenário", "Braço Experimental", "Assistente", "Linguagem", 
        "Repetição", "Arquivo", "Ferramenta", "Linha", 
        "ID CWE", "Categoria OWASP 2025", "Severidade Normalizada", "Desfecho Triagem"
    ]
    df = df[colunas_ordem]
    
    # Exporta o arquivo blindado
    df.to_excel(caminho_excel, index=False)
    print(f"Sucesso! Matriz exportada para: {caminho_excel}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 scripts/extrator_sast.py <caminho_do_cenario>")
    else:
        pasta_cenario_alvo = sys.argv[1]
        nome_cenario = os.path.basename(os.path.normpath(pasta_cenario_alvo)).upper()
        consolidar_e_exportar(pasta_cenario_alvo, nome_cenario)