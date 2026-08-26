import os
import sys
import json
import pandas as pd

# ==============================================================================
# 1. REGRAS DE NEGÓCIO E MAPEAMENTO (OWASP E SEVERIDADE)
# ==============================================================================

# Dicionário dinâmico mapeando CWEs e Regras do Snyk para o OWASP Top 10 (2025)
MAPEAMENTO_OWASP = {
    # Injection (A03:2021 -> A05:2025)
    "CWE-89": "A05:2025 - Injection",
    "CWE-915": "A05:2025 - Injection",
    "CWE-704": "A05:2025 - Injection",
    "python/Sqli": "A05:2025 - Injection",
    
    # Broken Access Control (A01:2021)
    "CWE-285": "A01:2021 - Broken Access Control",
    "CWE-200": "A01:2021 - Broken Access Control",
    
    # Identification and Authentication Failures (A07:2021)
    "CWE-798": "A07:2021 - Identification and Authentication Failures",
    "CWE-547": "A07:2021 - Identification and Authentication Failures",
    "python/HardcodedNonCryptoSecret": "A07:2021 - Identification and Authentication Failures",
    
    # Security Misconfiguration (A06:2021)
    "CWE-489": "A06:2021 - Security Misconfiguration",
    "python/RunWithDebugTrue": "A06:2021 - Security Misconfiguration"
}

def obter_categoria_owasp(id_regra):
    # Procura a regra exata, senão procura o prefixo CWE
    regra_limpa = str(id_regra).split(':')[0].strip()
    return MAPEAMENTO_OWASP.get(regra_limpa, MAPEAMENTO_OWASP.get(id_regra, "Outro / Não Mapeado"))

def normalizar_severidade(ferramenta, severidade_original):
    sev = str(severidade_original).upper()
    if ferramenta == "Snyk Code":
        # Snyk sarif usa error, warning, note
        if sev == "ERROR": return "Alta"
        if sev == "WARNING": return "Média"
        if sev == "NOTE": return "Baixa"
    elif ferramenta == "Semgrep":
        if sev in ["ERROR", "HIGH"]: return "Alta"
        if sev in ["WARNING", "MEDIUM"]: return "Média"
        if sev in ["INFO", "LOW"]: return "Baixa"
    return "Não Classificada"

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
        cwe_info = issue.get("extra", {}).get("metadata", {}).get("cwe", ["CWE-Desconhecido"])
        if isinstance(cwe_info, list) and len(cwe_info) > 0: cwe_info = cwe_info[0]
        
        registro = {
            **metadados,
            "Ferramenta": "Semgrep",
            "Linha": issue.get("start", {}).get("line", 0),
            "ID CWE": cwe_info,
            "Categoria OWASP 2025": obter_categoria_owasp(cwe_info),
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
        for result in run.get("results", []):
            locations = result.get("locations", [])
            if not locations: continue
            arquivo = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            metadados = parse_nome_arquivo(arquivo)
            if not metadados: continue
            
            rule_id = result.get("ruleId", "")
            
            registro = {
                **metadados,
                "Ferramenta": "Snyk Code",
                "Linha": locations[0].get("physicalLocation", {}).get("region", {}).get("startLine", 0),
                "ID CWE": rule_id, 
                "Categoria OWASP 2025": obter_categoria_owasp(rule_id),
                "Severidade Normalizada": normalizar_severidade("Snyk Code", result.get("level", "note")),
                "Desfecho Triagem": "" 
            }
            achados.append(registro)
    return achados

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
    
    # Chama as funções de extração (que você já tem prontas)
    dados_totais = processar_semgrep(semgrep_json) + processar_snyk(snyk_json)
    
    if not dados_totais:
        print("Nenhum dado encontrado ou arquivos JSON ausentes/vazios.")
        return
        
    df = pd.DataFrame(dados_totais)
    df = df.drop_duplicates(subset=['Arquivo', 'Linha', 'ID CWE'], keep='first')
    
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