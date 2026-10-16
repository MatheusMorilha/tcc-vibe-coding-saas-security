'use strict';

/**
 * POST /api/usuarios
 * Dependências: express helmet express-rate-limit zod argon2 pg
 *
 * Contrato do middleware de autenticação (não incluído aqui):
 *   `authenticate` valida o JWT/sessão e define req.auth = { userId, tenantId, papel }
 *   `exigirPapel('admin')` bloqueia quem não for administrador do tenant.
 *
 * Esquema mínimo esperado (PostgreSQL):
 *   CREATE TABLE usuarios (
 *     id         UUID PRIMARY KEY,
 *     tenant_id  UUID NOT NULL REFERENCES tenants(id),
 *     nome       VARCHAR(120) NOT NULL,
 *     email      VARCHAR(254) NOT NULL,
 *     senha_hash TEXT NOT NULL,
 *     papel      VARCHAR(20) NOT NULL DEFAULT 'membro',
 *     ativo      BOOLEAN NOT NULL DEFAULT TRUE,
 *     criado_em  TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 *   -- unicidade de e-mail POR empresa, garantida pelo banco (evita race condition)
 *   CREATE UNIQUE INDEX usuarios_tenant_email_uq ON usuarios (tenant_id, lower(email));
 */

const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const argon2 = require('argon2');
const { Pool } = require('pg');
const { authenticate, exigirPapel } = require('./middlewares/auth');

// ---------------------------------------------------------------------------
// Banco de dados (A02/A05: TLS e credenciais via variável de ambiente)
// ---------------------------------------------------------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
  max: 20,
  statement_timeout: 5000,
});

// ---------------------------------------------------------------------------
// Validação de entrada (A03/A04): allowlist de campos, tipos e tamanhos.
// .strict() rejeita campos extras => impede mass assignment
// (ex.: o cliente enviar "papel", "tenant_id" ou "ativo").
// ---------------------------------------------------------------------------
const criarUsuarioSchema = z
  .object({
    nome: z.string().trim().min(2).max(120),
    email: z.string().trim().toLowerCase().email().max(254),
    // Limite superior evita DoS no hashing; 12+ caracteres conforme NIST 800-63B
    senha: z.string().min(12).max(128),
  })
  .strict();

// A04/A07: rate limit contra criação em massa e abuso
const limitador = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { erro: 'Muitas requisições. Tente novamente mais tarde.' },
});

// A02: Argon2id (parâmetros mínimos recomendados pela OWASP)
const ARGON2_OPTS = {
  type: argon2.argon2id,
  memoryCost: 19456, // ~19 MiB
  timeCost: 2,
  parallelism: 1,
};

// ---------------------------------------------------------------------------
// Rota
// ---------------------------------------------------------------------------
const router = express.Router();

router.post(
  '/',
  limitador,
  authenticate, // A01/A07: exige identidade verificada
  exigirPapel('admin'), // A01: controle de acesso por função
  async (req, res, next) => {
    // 1) Validação
    const parsed = criarUsuarioSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        erro: 'Dados inválidos.',
        // Não ecoa os valores recebidos, só campo e regra violada
        detalhes: parsed.error.issues.map((i) => ({
          campo: i.path.join('.'),
          mensagem: i.message,
        })),
      });
    }

    const { nome, email, senha } = parsed.data;

    // A01 (isolamento multilocatário): tenant SEMPRE vem da sessão autenticada
    const { tenantId, userId: atorId } = req.auth;

    // 2) Hash fora da transação, para não segurar lock durante o cálculo
    let senhaHash;
    try {
      senhaHash = await argon2.hash(senha, ARGON2_OPTS);
    } catch (err) {
      return next(err);
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // 3) Regra de negócio: assinatura ativa e limite de usuários do plano.
      //    FOR UPDATE no tenant serializa cadastros concorrentes e impede
      //    estourar o limite do plano (race condition).
      const { rows: plano } = await client.query(
        `SELECT p.max_usuarios,
                (SELECT COUNT(*) FROM usuarios u
                  WHERE u.tenant_id = $1 AND u.ativo) AS total
           FROM tenants t
           JOIN planos p ON p.id = t.plano_id
          WHERE t.id = $1 AND t.assinatura_ativa = TRUE
            FOR UPDATE OF t`,
        [tenantId]
      );

      if (plano.length === 0) {
        await client.query('ROLLBACK');
        return res.status(403).json({ erro: 'Assinatura inativa ou inexistente.' });
      }
      if (Number(plano[0].total) >= plano[0].max_usuarios) {
        await client.query('ROLLBACK');
        return res.status(403).json({ erro: 'Limite de usuários do plano atingido.' });
      }

      // 4) Persistência (A03: query parametrizada, sem concatenação de string).
      //    O papel é fixo no servidor, nunca vem do cliente.
      const { rows } = await client.query(
        `INSERT INTO usuarios (id, tenant_id, nome, email, senha_hash, papel)
         VALUES ($1, $2, $3, $4, $5, 'membro')
         RETURNING id, nome, email, papel, criado_em`,
        [crypto.randomUUID(), tenantId, nome, email, senhaHash]
      );

      await client.query('COMMIT');

      // A09: log estruturado de auditoria, sem senha, hash ou e-mail
      console.info(
        JSON.stringify({
          evento: 'usuario.criado',
          tenantId,
          atorId,
          usuarioId: rows[0].id,
          ip: req.ip,
          ts: new Date().toISOString(),
        })
      );

      // 5) Resposta: nunca devolve senha_hash nem tenant_id
      const u = rows[0];
      res.set('Cache-Control', 'no-store');
      res.set('Location', `/api/usuarios/${u.id}`);
      return res.status(201).json({
        id: u.id,
        nome: u.nome,
        email: u.email,
        papel: u.papel,
        criadoEm: u.criado_em,
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});

      // Violação do índice único (tenant_id, lower(email))
      if (err.code === '23505') {
        return res.status(409).json({ erro: 'E-mail já cadastrado nesta empresa.' });
      }
      return next(err);
    } finally {
      client.release();
    }
  }
);

// ---------------------------------------------------------------------------
// App (A05: configuração segura)
// ---------------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // ajuste conforme sua infraestrutura (necessário p/ req.ip e rate limit)
app.use(helmet());
app.use(express.json({ limit: '10kb' })); // limita o tamanho do corpo
app.use('/api/usuarios', router);

// A09/A05: erro genérico ao cliente, detalhe apenas no log interno
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  const idErro = crypto.randomUUID();
  console.error(
    JSON.stringify({ evento: 'erro.interno', idErro, mensagem: err.message, stack: err.stack })
  );
  res.status(500).json({ erro: 'Erro interno.', idErro });
});

module.exports = app;