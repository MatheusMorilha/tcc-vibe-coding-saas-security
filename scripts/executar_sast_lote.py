import os
import sys
import subprocess

def executar_sast_no_cenario(caminho_cenario):
    if not os.path.exists(caminho_cenario):
        print(f"Erro: O caminho '{caminho_cenario}' não existe.")
        return

    print(f"\n==================================================")
    print(f" Executando varredura SAST no cenário: {caminho_cenario}")
    print(f"==================================================\n")

    # 1. Executa Semgrep
    print(" Running Semgrep...")
    cmd_semgrep = 'semgrep scan --exclude="*.json" --json > resultado_semgrep.json'
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
        # Pega o argumento passado pelo terminal (ex: amostras/principal/P01)
        executar_sast_no_cenario(sys.argv[1])