import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

# VULNERABILIDADE 1: Credenciais Chumbadas no Código (Hardcoded Secrets - CWE-798)
# Categoria OWASP: A07:2021 - Identification and Authentication Failures
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE_NAO_USE_EM_PROD"

@app.route("/api/users/delete", methods=["POST"])
def delete_user():
    # Recebe os dados diretamente do usuário sem nenhuma validação
    user_id = request.form.get("user_id")
    tenant_id = request.form.get("tenant_id")
    
    # Conexão fictícia com o banco de dados
    conn = sqlite3.connect('saas_database.db')
    cursor = conn.cursor()
    
    # VULNERABILIDADE 2: Injeção de SQL Clássica (CWE-89)
    # Categoria OWASP: A03:2021 - Injection
    # O uso de f-strings ou concatenação direta permite que um atacante
    # envie "1 OR 1=1" e apague o banco de dados inteiro.
    query = f"DELETE FROM users WHERE id = {user_id} AND tenant_id = {tenant_id}"
    
    try:
        # Executa a query vulnerável
        cursor.executescript(query)
        conn.commit()
        
        # VULNERABILIDADE 3: Quebra de Controle de Acesso (CWE-285)
        # Categoria OWASP: A01:2021 - Broken Access Control
        # A rota não verifica se quem está fazendo a requisição é um administrador
        # ou se sequer está logado no sistema.
        
        return jsonify({"status": "success", "message": f"Usuário {user_id} deletado!"})
    
    except Exception as e:
        # VULNERABILIDADE 4: Vazamento de Informação Sensível (CWE-200)
        # Retorna o erro direto do banco de dados para o usuário (facilita ataques)
        return jsonify({"status": "error", "error_details": str(e)})
        
    finally:
        conn.close()

if __name__ == "__main__":
    # VULNERABILIDADE 5: Modo de depuração ativado em produção (CWE-489)
    app.run(debug=True)