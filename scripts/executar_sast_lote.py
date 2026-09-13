import os
import sys
import subprocess

def executar_sast_no_cenario(caminho_cenario):
    if not os.path.exists(caminho_cenario):
        print(f"Erro: O caminho '{caminho_cenario}' não existe.")
        return

    # ==================================================================
    # MEDIDA DE SEGURANÇA: Prevenir re-execução do mesmo lote
    # ==================================================================
    caminho_semgrep = os.path.join(caminho_cenario, "resultado_semgrep.json")
    caminho_snyk = os.path.join(caminho_cenario, "resultado_snyk.json")
    
    if os.path.exists(caminho_semgrep) or os.path.exists(caminho_snyk):
        print(f"\n⚠️ AVISO: O cenário '{caminho_cenario}' já foi analisado anteriormente!")
        print("Os relatórios JSON já existem nesta pasta.")
        print("Modo de segurança: Execução abortada para evitar sobrescrita e retrabalho.\n")
        return

    print(f"\n==================================================")
    print(f" Executando varredura SAST no cenário: {caminho_cenario}")
    print(f"==================================================\n")

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
    subprocess.run(cmd_semgrep, shell=True, cwd=caminho_cenario)

    # 2. Executa Snyk Code
    print(" Running Snyk Code...")
    cmd_snyk = "snyk code test --json > resultado_snyk.json"
    subprocess.run(cmd_snyk, shell=True, cwd=caminho_cenario)

    print(f"\n Varredura concluída com sucesso para {caminho_cenario}!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 scripts/executar_sast_lote.py <caminho_do_cenario>")
        print("Exemplo: python3 scripts/executar_sast_lote.py amostras/principal/P01")
    else:
        executar_sast_no_cenario(sys.argv[1])