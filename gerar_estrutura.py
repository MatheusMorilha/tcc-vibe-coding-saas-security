import os

# 1. Definição das Variáveis do Experimento
bracos = {
    "PRINCIPAL": range(1, 31),  # C01 ao C30
    "CONTROLE": range(1, 11)    # C01 ao C10
}
assistentes = ["CHATGPT", "CLAUDE", "COPILOT"]
linguagens = {"PY": "py", "NODE": "js"}
repeticoes = ["REP1", "REP2", "REP3"]

# 2. Criação da pasta raiz
pasta_raiz = "tcc_amostras"
os.makedirs(pasta_raiz, exist_ok=True)

contador = 0

# 3. Laço de repetição para gerar e separar os 720 arquivos
for braco, cenarios in bracos.items():
    # Cria a subpasta para o braço atual (principal ou controle)
    pasta_braco = os.path.join(pasta_raiz, braco.lower())
    os.makedirs(pasta_braco, exist_ok=True)

    for num_cenario in cenarios:
        cenario = f"C{num_cenario:02d}" # Formata com zero à esquerda (ex: C01)
        
        for assistente in assistentes:
            for lang, ext in linguagens.items():
                for rep in repeticoes:
                    # Monta o nome padronizado do arquivo
                    nome_arquivo = f"{braco}_{cenario}_{assistente}_{lang}_{rep}.{ext}"
                    caminho_completo = os.path.join(pasta_braco, nome_arquivo)
                    
                    # Cria o arquivo vazio dentro da pasta correspondente
                    with open(caminho_completo, 'w') as f:
                        pass # Arquivo gerado em branco
                    
                    contador += 1

print(f"Sucesso! {contador} arquivos criados, separados nas pastas 'principal' e 'controle' dentro de '{pasta_raiz}'.")