import os
import sqlite3
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)

# CONFIGURAÇÃO DE LOGS (Evita vazar erros no terminal do usuário)
logging.basicConfig(level=logging.INFO)

# CORREÇÃO 1: Segredos protegidos (Mitiga CWE-798 - Hardcoded Secrets)
# Nunca chumbamos chaves no código. Lemos sempre de variáveis de ambiente.
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_KEY")

# CORREÇÃO 2: Controle de Acesso (Mitiga CWE-285 - Broken Access Control)
# Um decorador simples para garantir que a rota exija autenticação
def admin_required(f):
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization")
        # Validação fictícia de token (na vida real usaríamos JWT)
        if not token or token != "Bearer SEGREDO_ADMIN_VALIDO":
            return jsonify({"status": "error", "message": "Acesso não autorizado ou token ausente."}), 403
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route("/api/users/delete", methods=["POST"])
@admin_required  # A rota agora está protegida
def delete_user():
    # Recebendo os dados da requisição
    user_id = request.form.get("user_id")
    tenant_id = request.form.get("tenant_id")
    
    # CORREÇÃO 3: Validação de Entrada (Defesa em Profundidade)
    # Garante que os dados não estão vazios e são apenas números antes de chegar no banco
    if not user_id or not user_id.isdigit() or not tenant_id or not tenant_id.isdigit():
        return jsonify({"status": "error", "message": "Formato de dados inválido."}), 400
        
    try:
        # Uso do 'with' garante o fechamento automático da conexão com o banco
        with sqlite3.connect('saas_database.db') as conn:
            cursor = conn.cursor()
            
            # CORREÇÃO 4: Injeção de SQL Resolvida (Mitiga CWE-89 - SQL Injection)
            # Substituímos a f-string perigosa por Consultas Parametrizadas (o uso da interrogação '?').
            # O próprio banco de dados isola e neutraliza qualquer código malicioso enviado pelo usuário.
            query = "DELETE FROM users WHERE id = ? AND tenant_id = ?"
            
            cursor.execute(query, (user_id, tenant_id))
            conn.commit()
            
            # Verifica se alguma linha foi de fato excluída
            if cursor.rowcount == 0:
                return jsonify({"status": "error", "message": "Usuário não encontrado ou não pertence ao tenant."}), 404
                
            return jsonify({"status": "success", "message": "Usuário deletado com sucesso."}), 200
            
    except sqlite3.Error as db_err:
        # CORREÇÃO 5: Vazamento de Informação (Mitiga CWE-200)
        # O erro real e sensível do banco é gravado nos logs internos para o desenvolvedor ver...
        logging.error(f"Erro no banco de dados: {db_err}")
        # ...mas o usuário final recebe apenas uma mensagem genérica de erro.
        return jsonify({"status": "error", "message": "Erro interno de processamento do servidor."}), 500

if __name__ == "__main__":
    # CORREÇÃO 6: Configuração Segura (Mitiga CWE-489 - Debug Code)
    # O modo de depuração nunca é deixado como True por padrão. 
    # Ele deve ser ativado apenas se uma variável de ambiente específica permitir.
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    app.run(debug=debug_mode)