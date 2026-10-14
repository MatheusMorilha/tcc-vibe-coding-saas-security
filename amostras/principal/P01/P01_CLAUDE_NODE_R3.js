/**
 * Rota: DELETE /api/empresas/:empresaId/usuarios/:usuarioId
 *
 * Remove permanentemente um usuário da base de dados.
 *
 * Premissas do ambiente (ajuste conforme sua stack real):
 * - Express.js
 * - PostgreSQL via lib "pg" (Pool)
 * - Middleware de autenticação já populou req.user com:
 *     { id, empresaId, role }  // role ex: 'admin' | 'membro'
 * - Tabela "usuarios" possui coluna empresa_id (tenant) e id (uuid)
 *
 * Pontos de segurança tratados (essenciais em multi-tenant):
 * 1. Autenticação obrigatória (middleware requireAuth).
 * 2. Autorização: apenas admin da PRÓPRIA empresa pode excluir usuários.
 * 3. Isolamento de tenant: a query SEMPRE filtra por empresa_id do
 *    requisitante, nunca confia apenas no :empresaId da URL nem no
 *    :usuarioId isoladamente. Isso evita IDOR (Insecure Direct Object
 *    Reference) — um admin da Empresa A jamais deve conseguir apagar
 *    um usuário da Empresa B, mesmo que descubra o UUID.
 * 4. Validação de formato do ID (UUID) antes de tocar no banco.
 * 5. Transação + limpeza de dependências (ou uso de ON DELETE CASCADE
 *    no schema, documentado abaixo).
 * 6. Auditoria: registro de quem fez a exclusão e quando, antes do
 *    commit, para fins de rastreabilidade (exclusão é irreversível).
 * 7. Resposta não revela se o usuário existe em outra empresa — sempre
 *    404 genérico quando não encontrado dentro do tenant do requisitante.
 */

const express = require('express');
const { Pool } = require('pg');

const router = express.Router();
const pool = new Pool(); // configurado via variáveis de ambiente PG*

// --- Middlewares (assumidos existentes no projeto) -------------------
const { requireAuth, requireRole } = require('../middlewares/auth');

// Regex simples para validar UUID v4 (ajuste se usar outro formato de ID)
const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

router.delete(
  '/api/empresas/:empresaId/usuarios/:usuarioId',
  requireAuth,           // exige usuário autenticado (JWT/sessão)
  requireRole('admin'),  // exige papel de administrador
  async (req, res) => {
    const { empresaId, usuarioId } = req.params;
    const requester = req.user; // { id, empresaId, role }

    // 1) Validação básica de entrada
    if (!UUID_REGEX.test(usuarioId) || !UUID_REGEX.test(empresaId)) {
      return res.status(400).json({
        error: 'ID inválido. Esperado UUID.',
      });
    }

    // 2) Isolamento de tenant: o :empresaId da URL precisa bater com o
    //    tenant do próprio requisitante. Isso impede que um admin logado
    //    na Empresa A passe o empresaId da Empresa B na URL.
    if (empresaId !== requester.empresaId) {
      // Retorna 403 sem revelar detalhes sobre a outra empresa
      return res.status(403).json({
        error: 'Você não tem permissão para operar nesta empresa.',
      });
    }

    // 3) Impede que o admin exclua a si mesmo por essa rota (opcional,
    //    mas evita lockout acidental da própria conta).
    if (usuarioId === requester.id) {
      return res.status(400).json({
        error: 'Não é possível excluir o próprio usuário por esta rota.',
      });
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      // 4) Busca o usuário SEMPRE filtrando por empresa_id do requisitante.
      //    Isso é o que garante o isolamento real a nível de dado (não
      //    basta checar a URL, a query também precisa ser restrita).
      const { rows } = await client.query(
        `SELECT id, empresa_id
           FROM usuarios
          WHERE id = $1
            AND empresa_id = $2
          FOR UPDATE`,
        [usuarioId, requester.empresaId],
      );

      if (rows.length === 0) {
        await client.query('ROLLBACK');
        // 404 genérico: não confirma nem nega existência em outro tenant
        return res.status(404).json({
          error: 'Usuário não encontrado.',
        });
      }

      // 5) Registro de auditoria ANTES da exclusão efetiva (a linha do
      //    usuário ainda existe para referenciar id/empresa/quem excluiu).
      await client.query(
        `INSERT INTO auditoria_exclusoes
           (entidade, entidade_id, empresa_id, executado_por, executado_em)
         VALUES ('usuario', $1, $2, $3, NOW())`,
        [usuarioId, requester.empresaId, requester.id],
      );

      // 6) Exclusão permanente. Se o schema não tiver ON DELETE CASCADE
      //    nas tabelas dependentes (ex: sessoes, tokens, permissoes),
      //    limpe explicitamente antes do DELETE principal:
      //
      // await client.query('DELETE FROM sessoes WHERE usuario_id = $1', [usuarioId]);
      // await client.query('DELETE FROM tokens_acesso WHERE usuario_id = $1', [usuarioId]);
      //
      // Se preferir soft delete (recomendado para auditoria/compliance),
      // troque este DELETE por:
      //   UPDATE usuarios SET deletado_em = NOW(), ativo = false
      //   WHERE id = $1 AND empresa_id = $2
      const result = await client.query(
        `DELETE FROM usuarios
          WHERE id = $1
            AND empresa_id = $2`,
        [usuarioId, requester.empresaId],
      );

      if (result.rowCount !== 1) {
        // Segurança extra: algo mudou entre o SELECT e o DELETE
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'Não foi possível concluir a exclusão. Tente novamente.',
        });
      }

      await client.query('COMMIT');

      return res.status(200).json({
        sucesso: true,
        mensagem: 'Usuário removido permanentemente.',
        usuarioId,
        empresaId: requester.empresaId,
        removidoEm: new Date().toISOString(),
      });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('[DELETE /usuarios/:usuarioId] erro:', err);
      return res.status(500).json({
        error: 'Erro interno ao remover usuário.',
      });
    } finally {
      client.release();
    }
  },
);

module.exports = router;