import os

# 1. Definição das Variáveis do Experimento conforme TCC
bracos = {
    "principal": {"prefixo": "P", "range": range(1, 31)},  # P01 a P30
    "controle": {"prefixo": "K", "range": range(1, 11)}    # K01 a K10
}
assistentes = ["CHATGPT", "CLAUDE", "COPILOT"]
linguagens = {"PY": "py", "NODE": "js"}
repeticoes = ["R1", "R2", "R3"]

pasta_raiz = "amostras"
contador_criados = 0
contador_ignorados = 0

# ==================================================================
# MEDIDA DE SEGURANÇA
# Verifica se a pasta já existe e informa o usuário no terminal
# ==================================================================
if os.path.exists(pasta_raiz):
    print(f"⚠️ AVISO: A pasta '{pasta_raiz}' já existe no diretório!")
    print("Modo de segurança ativado: Nenhum arquivo existente será sobrescrito ou apagado.\n")
else:
    print(f"Iniciando a criação da estrutura em '{pasta_raiz}'...\n")

# 2. Laço de repetição para gerar pastas e arquivos
for nome_braco, config in bracos.items():
    for num_cenario in config["range"]:
        # Formata o cenário (ex: P01, K10)
        cenario = f"{config['prefixo']}{num_cenario:02d}" 
        
        # Cria a pasta aninhada: ex: amostras/principal/P01
        pasta_cenario = os.path.join(pasta_raiz, nome_braco, cenario)
        os.makedirs(pasta_cenario, exist_ok=True)
        
        for assistente in assistentes:
            for lang, ext in linguagens.items():
                for rep in repeticoes:
                    # Monta o nome padronizado do arquivo segundo o TCC
                    # Exemplo: P13_CLAUDE_PY_R2.py
                    nome_arquivo = f"{cenario}_{assistente}_{lang}_{rep}.{ext}"
                    caminho_completo = os.path.join(pasta_cenario, nome_arquivo)
                    
                    # MEDIDA DE SEGURANÇA: Só cria se o arquivo NÃO existir
                    if not os.path.exists(caminho_completo):
                        # Cria o arquivo vazio dentro da pasta do cenário
                        with open(caminho_completo, 'w') as f:
                            pass
                        contador_criados += 1
                    else:
                        # Se já existe, ignora e contabiliza como preservado
                        contador_ignorados += 1

# 3. Relatório Final no Terminal
print("==================================================")
print("Resumo da Execução:")
print(f" -> Novos arquivos criados: {contador_criados}")
print(f" -> Arquivos preservados (não sobrescritos): {contador_ignorados}")
print("==================================================")