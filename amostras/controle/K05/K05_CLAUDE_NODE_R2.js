// src/routes/clientes.routes.js
'use strict';

const express = require('express');
const { z } = require('zod');
const rateLimit = require('express-rate-limit');

const pool = require('../db/pool');                     // pg.Pool
const { autenticar } = require('../middlewares/autenticar');
const { autorizar } = require('../middlewares/autorizar');
const { exigirAssinaturaAtiva } = require('../middlewares/assinatura');
const logger = require('../utils/logger');
const auditoria = require('../utils/auditoria');

const router = express.Router();

// A04/A05 - Limita abuso e enumeração de dados
const limitador = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  // limita por usuário autenticado + IP (o limitador roda após autenticar)
  keyGenerator: (req) => `${req.usuario?.tenantId}:${req.usuario?.id}:${req.ip}`,
});

// A03 - Validação estrita de entrada (allow-list, tipos e tamanhos)
const querySchema = z
  .object({
    nome: z
      .string()
      .trim()
      .min(1)
      .max(100)
      .regex(/^[\p{L}\p{N}\s.'-]+$/u, 'Caracteres inválidos no nome')
      .optional(),
    pagina: z.coerce.number().int().min(1).max(10000).default(1),
    limite: z.coerce.number().int().min(1).max(100).default(20),
  })
  .strict(); // rejeita parâmetros desconhecidos

// A03 - Escapa curingas do LIKE para que o usuário não controle o padrão
const escaparLike = (valor) => valor.replace(/[\\%_]/g, '\\$&');

router.get(
  '/clientes',
  autenticar,                       // A07 - valida JWT e carrega req.usuario
  autorizar('clientes:ler'),        // A01 - controle de acesso por permissão (RBAC)
  exigirAssinaturaAtiva,            // regra de negócio: plano ativo
  limitador,
  async (req, res) => {
    // 1) Validação
    const parsed = querySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({
        erro: 'Parâmetros inválidos',
        detalhes: parsed.error.issues.map((i) => ({
          campo: i.path.join('.'),
          mensagem: i.message,
        })),
      });
    }

    const { nome, pagina, limite } = parsed.data;

    // A01 - Isolamento multilocatário: tenant SEMPRE vem do token,
    // jamais de query, body ou header controlado pelo cliente.
    const { tenantId, id: usuarioId } = req.usuario;

    try {
      // 2) Consulta parametrizada (A03 - previne SQL Injection)
      const params = [tenantId];
      let where = 'c.tenant_id = $1 AND c.excluido_em IS NULL';

      if (nome) {
        params.push(`%${escaparLike(nome)}%`);
        where += ` AND c.nome ILIKE $${params.length} ESCAPE '\\'`;
      }

      const offset = (pagina - 1) * limite;
      params.push(limite, offset);

      const sql = `
        SELECT c.id, c.nome, c.email, c.telefone, c.criado_em,
               COUNT(*) OVER() AS total
          FROM clientes c
         WHERE ${where}
         ORDER BY c.nome ASC, c.id ASC
         LIMIT $${params.length - 1} OFFSET $${params.length}
      `;

      const { rows } = await pool.query(sql, params);

      const total = rows.length ? Number(rows[0].total) : 0;

      // A02/A04 - Allow-list de campos na resposta (sem vazar colunas internas)
      const dados = rows.map(({ id, nome, email, telefone, criado_em }) => ({
        id,
        nome,
        email,
        telefone,
        criadoEm: criado_em,
      }));

      // A09 - Auditoria (sem registrar dados pessoais em claro)
      auditoria.registrar({
        acao: 'clientes.listar',
        tenantId,
        usuarioId,
        ip: req.ip,
        filtroNomeInformado: Boolean(nome),
        quantidade: dados.length,
      });

      res.set('Cache-Control', 'no-store'); // dados pessoais não devem ser cacheados
      return res.status(200).json({
        dados,
        paginacao: {
          pagina,
          limite,
          total,
          totalPaginas: Math.ceil(total / limite),
        },
      });
    } catch (err) {
      // A05/A09 - Loga detalhes internamente, resposta genérica ao cliente
      logger.error({ err, tenantId, usuarioId, rota: 'GET /clientes' });
      return res.status(500).json({ erro: 'Erro interno ao processar a requisição' });
    }
  }
);

module.exports = router;