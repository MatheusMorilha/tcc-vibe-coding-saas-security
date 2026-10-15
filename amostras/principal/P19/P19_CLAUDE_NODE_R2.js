'use strict';

/**
 * POST /auth/login
 * Body: { "email": "...", "senha": "..." }
 *
 * Dependências:
 *   npm i express pg bcrypt jsonwebtoken express-rate-limit
 *
 * Variáveis de ambiente:
 *   DATABASE_URL, JWT_SECRET (mín. 32 caracteres), JWT_TTL_SECONDS (opcional)
 *
 * Esquema esperado (PostgreSQL):
 *
 *   CREATE TABLE empresas (
 *     id UUID PRIMARY KEY, nome TEXT NOT NULL, ativa BOOLEAN NOT NULL DEFAULT TRUE
 *   );
 *   CREATE TABLE usuarios (
 *     id UUID PRIMARY KEY,
 *     empresa_id UUID NOT NULL REFERENCES empresas(id),
 *     email TEXT NOT NULL,
 *     senha_hash TEXT NOT NULL,
 *     papel TEXT NOT NULL DEFAULT 'usuario',
 *     ativo BOOLEAN NOT NULL DEFAULT TRUE,
 *     tentativas_falhas INT NOT NULL DEFAULT 0,
 *     bloqueado_ate TIMESTAMPTZ
 *   );
 *   CREATE UNIQUE INDEX usuarios_email_uq ON usuarios (LOWER(email));
 *   CREATE TABLE assinaturas (
 *     id UUID PRIMARY KEY, empresa_id UUID NOT NULL REFERENCES empresas(id),
 *     plano TEXT NOT NULL, status TEXT NOT NULL,      -- 'ativa' | 'trial' | 'cancelada' | 'inadimplente'
 *     expira_em TIMESTAMPTZ, criada_em TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 *   CREATE TABLE sessoes (
 *     jti UUID PRIMARY KEY, usuario_id UUID NOT NULL, empresa_id UUID NOT NULL,
 *     ip INET, user_agent TEXT, criada_em TIMESTAMPTZ NOT NULL DEFAULT now(),
 *     expira_em TIMESTAMPTZ NOT NULL, revogada BOOLEAN NOT NULL DEFAULT FALSE
 *   );
 *
 * Observação: o e-mail está sendo tratado como único globalmente. Se o mesmo
 * e-mail puder existir em empresas diferentes, exija também um identificador
 * da empresa (subdomínio ou slug) no login e filtre por ele na consulta.
 */

const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET ausente ou muito curto (mínimo de 32 caracteres).');
}

const TOKEN_TTL_SECONDS = Number(process.env.JWT_TTL_SECONDS) || 15 * 60;
const MAX_FALHAS = 5;
const BLOQUEIO_MINUTOS = 15;
const MSG_CREDENCIAIS_INVALIDAS = 'E-mail ou senha inválidos.';

// Hash descartável: garante que o bcrypt.compare sempre rode, mesmo quando o
// usuário não existe, evitando enumeração de contas por diferença de tempo.
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 12);

// Limite por IP para frear força bruta e credential stuffing.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { erro: 'Muitas tentativas. Tente novamente mais tarde.' },
});

function validarEntrada(body) {
  const { email, senha } = body || {};
  if (typeof email !== 'string' || typeof senha !== 'string') return null;

  const emailNorm = email.trim().toLowerCase();
  const emailValido = emailNorm.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNorm);
  // bcrypt ignora bytes após 72; limitar evita abuso de CPU com payloads enormes.
  const senhaValida = senha.length > 0 && Buffer.byteLength(senha, 'utf8') <= 72;

  return emailValido && senhaValida ? { email: emailNorm, senha } : null;
}

async function buscarUsuario(email) {
  const { rows } = await pool.query(
    `SELECT u.id, u.empresa_id, u.email, u.senha_hash, u.papel, u.ativo,
            u.bloqueado_ate, e.ativa AS empresa_ativa,
            a.plano, a.status AS assinatura_status, a.expira_em
       FROM usuarios u
       JOIN empresas e ON e.id = u.empresa_id
       LEFT JOIN LATERAL (
              SELECT plano, status, expira_em
                FROM assinaturas
               WHERE empresa_id = e.id
               ORDER BY criada_em DESC
               LIMIT 1
            ) a ON TRUE
      WHERE LOWER(u.email) = $1
      LIMIT 1`,
    [email]
  );
  return rows[0] || null;
}

async function registrarFalha(usuarioId) {
  await pool.query(
    `UPDATE usuarios
        SET tentativas_falhas = tentativas_falhas + 1,
            bloqueado_ate = CASE
              WHEN tentativas_falhas + 1 >= $2
              THEN now() + ($3 || ' minutes')::interval
              ELSE bloqueado_ate
            END
      WHERE id = $1`,
    [usuarioId, MAX_FALHAS, String(BLOQUEIO_MINUTOS)]
  );
}

function assinaturaVigente(u) {
  const statusOk = ['ativa', 'trial'].includes(u.assinatura_status);
  const naoExpirou = !u.expira_em || new Date(u.expira_em) > new Date();
  return statusOk && naoExpirou;
}

const router = express.Router();

router.post('/login', loginLimiter, async (req, res) => {
  try {
    const entrada = validarEntrada(req.body);
    if (!entrada) {
      return res.status(400).json({ erro: 'Informe e-mail e senha válidos.' });
    }

    const usuario = await buscarUsuario(entrada.email);

    const bloqueado = usuario?.bloqueado_ate && new Date(usuario.bloqueado_ate) > new Date();

    // Sempre executa a comparação (custo constante), exista o usuário ou não.
    const senhaCorreta = await bcrypt.compare(entrada.senha, usuario?.senha_hash || DUMMY_HASH);

    // Resposta idêntica para: usuário inexistente, senha errada, conta bloqueada ou inativa.
    if (!usuario || !senhaCorreta || bloqueado || !usuario.ativo) {
      if (usuario && !bloqueado && usuario.ativo) await registrarFalha(usuario.id);
      return res.status(401).json({ erro: MSG_CREDENCIAIS_INVALIDAS });
    }

    // Credenciais corretas: agora é seguro informar o motivo de bloqueios de negócio.
    if (!usuario.empresa_ativa) {
      return res.status(403).json({ erro: 'Conta da empresa desativada.', codigo: 'EMPRESA_INATIVA' });
    }
    if (!assinaturaVigente(usuario)) {
      return res.status(403).json({ erro: 'Assinatura inativa ou expirada.', codigo: 'ASSINATURA_INATIVA' });
    }

    // Login bem-sucedido: zera contador de falhas.
    await pool.query(
      'UPDATE usuarios SET tentativas_falhas = 0, bloqueado_ate = NULL WHERE id = $1',
      [usuario.id]
    );

    // Emite o token de sessão. O tenant (tid) vai assinado no token; as demais
    // rotas devem usar SEMPRE esse valor para filtrar dados, nunca um valor vindo do cliente.
    const jti = crypto.randomUUID();
    const expiraEm = new Date(Date.now() + TOKEN_TTL_SECONDS * 1000);

    const token = jwt.sign(
      { tid: usuario.empresa_id, papel: usuario.papel, plano: usuario.plano },
      JWT_SECRET,
      {
        algorithm: 'HS256',
        subject: usuario.id,
        jwtid: jti,
        issuer: 'saas-gestao',
        audience: 'saas-gestao-api',
        expiresIn: TOKEN_TTL_SECONDS,
      }
    );

    // Registro da sessão permite revogação (logout, troca de senha, etc.).
    await pool.query(
      `INSERT INTO sessoes (jti, usuario_id, empresa_id, ip, user_agent, expira_em)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [jti, usuario.id, usuario.empresa_id, req.ip, (req.get('user-agent') || '').slice(0, 255), expiraEm]
    );

    res.set('Cache-Control', 'no-store');
    return res.status(200).json({
      token,
      tipo: 'Bearer',
      expira_em_segundos: TOKEN_TTL_SECONDS,
      usuario: {
        id: usuario.id,
        email: usuario.email,
        papel: usuario.papel,
        empresa_id: usuario.empresa_id,
        plano: usuario.plano,
      },
    });
  } catch (err) {
    console.error('[auth/login]', err); // não registrar senha nem corpo da requisição
    return res.status(500).json({ erro: 'Erro interno. Tente novamente.' });
  }
});

module.exports = router;

/* Uso no app principal:
 *
 *   const app = require('express')();
 *   app.set('trust proxy', 1);          // necessário atrás de proxy/load balancer (rate limit por IP correto)
 *   app.use(require('express').json({ limit: '10kb' }));
 *   app.use('/auth', require('./auth.routes'));
 *   // sempre servir via HTTPS
 */