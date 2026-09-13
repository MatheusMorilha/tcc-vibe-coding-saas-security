import os
import sys
import pandas as pd

def relatorio_arquivos_seguros(caminho_cenario):
    nome_cenario = os.path.basename(os.path.normpath(caminho_cenario)).upper()
    caminho_excel = os.path.join(caminho_cenario, f"matriz_rastreabilidade_{nome_cenario}.xlsx")
    
    # 1. Mapear todos os arquivos de código-fonte que existem na pasta
    todos_arquivos = [f for f in os.listdir(caminho_cenario) if f.endswith(('.py', '.js'))]

    if not todos_arquivos:
        print(f"Nenhum arquivo de código (.py ou .js) encontrado em '{caminho_cenario}'.")
        return

    # MEDIDA DE SEGURANÇA: separar arquivo vazio (Passo 1 ainda não feito nele)
    # de arquivo realmente preenchido. Um arquivo 0 bytes não é uma amostra
    # "segura" — é uma amostra que ainda não existe.
    arquivos_vazios = {
        f for f in todos_arquivos
        if os.path.getsize(os.path.join(caminho_cenario, f)) == 0
    }

    # 2. Ler o Excel para descobrir quais arquivos foram "reprovados"
    arquivos_vulneraveis = set()
    if os.path.exists(caminho_excel):
        df = pd.read_excel(caminho_excel)
        if 'Arquivo' in df.columns:
            # Pega apenas nomes únicos da coluna "Arquivo"
            arquivos_vulneraveis = set(df['Arquivo'].dropna().unique())

    arquivos_preenchidos = set(todos_arquivos) - arquivos_vazios
    arquivos_seguros = arquivos_preenchidos - arquivos_vulneraveis

    # 4. Imprimir o relatório
    print("\n" + "="*50)
    print(f" 📊 RELATÓRIO DE CÓDIGO SEGURO: {nome_cenario}")
    print("="*50)
    print(f"Total de Amostras Esperadas: {len(todos_arquivos)}")
    print(f"Amostras Ainda Vazias (Passo 1 pendente): {len(arquivos_vazios)}")
    print(f"Amostras Preenchidas: {len(arquivos_preenchidos)}")
    print(f"Amostras Vulneráveis (No Excel): {len(arquivos_vulneraveis)}")
    print(f"Amostras Preenchidas e Sem Achados (SAST Limpo): {len(arquivos_seguros)}\n")

    if arquivos_vazios:
        print("⏳ AINDA VAZIOS (faltando gerar/colar o código):")
        for arq in sorted(arquivos_vazios):
            print(f" - {arq}")
        print()

    if arquivos_seguros:
        print("🏆 ARQUIVOS PREENCHIDOS SEM VULNERABILIDADES:")
        for arq in sorted(arquivos_seguros):
            print(f" - {arq}")
    elif not arquivos_vazios:
        print("🚨 Nenhum arquivo seguro neste cenário. Todos apresentaram vulnerabilidades.")
    print("="*50 + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 scripts/verificar_seguros.py <caminho_do_cenario>")
        print("Exemplo: python3 scripts/verificar_seguros.py amostras/principal/P01")
    else:
        relatorio_arquivos_seguros(sys.argv[1])