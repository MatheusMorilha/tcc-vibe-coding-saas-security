import os
import sys
import json
import subprocess

# Códigos de saída considerados "execução normal" para cada ferramenta
# (encontrar ou não achados não é falha — falha é não conseguir rodar).
CODIGOS_OK_SEMGREP = {0, 1}
CODIGOS_OK_SNYK = {0, 1}


def validar_json_semgrep(caminho_json, codigo_saida):
    if codigo_saida not in CODIGOS_OK_SEMGREP:
        return False, f"Semgrep terminou com código de saída {codigo_saida} (esperado 0 ou 1)."

    if not os.path.exists(caminho_json) or os.path.getsize(caminho_json) == 0:
        return False, "resultado_semgrep.json não foi criado ou está vazio."

    try:
        with open(caminho_json, "r", encoding="utf-8") as f:
            dados = json.load(f)
    except json.JSONDecodeError:
        return False, "resultado_semgrep.json não é um JSON válido."

    if "results" not in dados:
        return False, "resultado_semgrep.json não contém a chave 'results' esperada."

    erros = dados.get("errors", [])
    if erros:
        return True, f"Semgrep relatou {len(erros)} erro(s) parcial(is) durante o scan (verifique 'errors' no JSON)."

    return True, None


def validar_json_snyk(caminho_json, codigo_saida):
    # Snyk: 0 = sem achados, 1 = achados encontrados, 2 = falha de execução
    # (ex.: sessão expirada), 3 = nenhum arquivo suportado encontrado.
    if codigo_saida == 2:
        return False, "Snyk Code terminou com código de saída 2 (falha de execução — confira 'snyk auth')."
    if codigo_saida == 3:
        return False, "Snyk Code terminou com código de saída 3 (nenhum arquivo suportado encontrado nesta pasta)."
    if codigo_saida not in CODIGOS_OK_SNYK:
        return False, f"Snyk Code terminou com código de saída {codigo_saida} (esperado 0 ou 1)."

    if not os.path.exists(caminho_json) or os.path.getsize(caminho_json) == 0:
        return False, "resultado_snyk.json não foi criado ou está vazio."

    try:
        with open(caminho_json, "r", encoding="utf-8") as f:
            dados = json.load(f)
    except json.JSONDecodeError:
        return False, "resultado_snyk.json não é um JSON válido."

    if "runs" not in dados or not dados["runs"]:
        return False, "resultado_snyk.json não contém a chave 'runs' (ou está vazia) — confira se o login (snyk auth) ainda está válido."

    return True, None


def executar_sast_no_cenario(caminho_cenario):
    if not os.path.exists(caminho_cenario):
        print(f"Erro: O caminho '{caminho_cenario}' não existe.")
        sys.exit(1)

    # ==================================================================
    # MEDIDA DE SEGURANÇA: Prevenir re-execução do mesmo lote
    # ==================================================================
    caminho_semgrep = os.path.join(caminho_cenario, "resultado_semgrep.json")
    caminho_snyk = os.path.join(caminho_cenario, "resultado_snyk.json")

    if os.path.exists(caminho_semgrep) or os.path.exists(caminho_snyk):
        print(f"\n⚠️ AVISO: O cenário '{caminho_cenario}' já foi analisado anteriormente!")
        print("Os relatórios JSON já existem nesta pasta.")
        print("Modo de segurança: Execução abortada para evitar sobrescrita e retrabalho.\n")
        sys.exit(1)

    print(f"\n==================================================")
    print(f" Executando varredura SAST no cenário: {caminho_cenario}")
    print(f"==================================================\n")

    houve_falha = False

    # 1. Executa Semgrep
    # Ruleset fixo e explícito (em vez do modo "auto"): garante que o mesmo
    # conjunto de regras seja usado em todos os cenários e que essa escolha
    # fique registrada, conforme a exigência de reprodutibilidade do projeto.
    # Ajuste esta lista uma única vez, no início da coleta, e não mude depois.
    print(" Running Semgrep...")
    cmd_semgrep = (
        'semgrep scan --quiet --exclude="*.json" --json '
        '--config=p/security-audit --config=p/owasp-top-ten --config=p/cwe-top-25 '
        '--config=p/python --config=p/nodejs '
        '> resultado_semgrep.json'
    )
    resultado_semgrep = subprocess.run(cmd_semgrep, shell=True, cwd=caminho_cenario)
    ok_semgrep, msg_semgrep = validar_json_semgrep(caminho_semgrep, resultado_semgrep.returncode)
    if not ok_semgrep:
        print(f" ❌ Semgrep: {msg_semgrep}")
        houve_falha = True
    elif msg_semgrep:
        print(f" ⚠️ Semgrep: {msg_semgrep}")
    else:
        print(" ✅ Semgrep concluído.")

    # 2. Executa Snyk Code
    print(" Running Snyk Code...")
    cmd_snyk = "snyk code test --json > resultado_snyk.json"
    resultado_snyk = subprocess.run(cmd_snyk, shell=True, cwd=caminho_cenario)
    ok_snyk, msg_snyk = validar_json_snyk(caminho_snyk, resultado_snyk.returncode)
    if not ok_snyk:
        print(f" ❌ Snyk Code: {msg_snyk}")
        houve_falha = True
    elif msg_snyk:
        print(f" ⚠️ Snyk Code: {msg_snyk}")
    else:
        print(" ✅ Snyk Code concluído.")

    if houve_falha:
        print(f"\n🚨 Varredura com FALHA para {caminho_cenario}.")
        print("Apague o(s) JSON(s) inválido(s) desta pasta e rode o script de novo depois de corrigir o problema apontado acima.\n")
        sys.exit(1)

    print(f"\n Varredura concluída com sucesso para {caminho_cenario}!")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 scripts/executar_sast_lote.py <caminho_do_cenario>")
        print("Exemplo: python3 scripts/executar_sast_lote.py amostras/principal/P01")
    else:
        executar_sast_no_cenario(sys.argv[1])