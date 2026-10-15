'use strict';

/**
 * Rota de autenticação - SaaS multilocatário (base compartilhada)
 *
 * Dependências:
 *   npm i express pg bcrypt jsonwebtoken express-rate-limit
 *
 * Variáveis de ambiente:
 *   DATABASE_URL  -> string de conexão do PostgreSQL
 *   JWT_SECRET    -> segredo longo e aleatório (>= 32 bytes)
 *   JWT_TTL       -> (opcional) validade do token, padrão "15m"
 *
 * Esquema esperado (resumo):
 *   empresas   (id, nome, ativa boolean)
 *   usuarios   (id, empresa_id, email UNIQUE, senha_hash, papel, ativo boolean)
 *   assinaturas(id, empresa_id, plano, status, expira_em timestamptz)
 *
 * Observação: aqui o e-mail é único globalmente. Se a sua regra permitir o
 * mesmo e-mail em empresas diferentes, o login deve receber também um
 * identificador do tenant (slug/subdomínio) e filtrar por ele na query.
 */

const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET ausente ou curto demais (mínimo 32 caracteres).');
}

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_TTL = process.env.JWT_TTL || '15m';
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Hash falso usado para igualar o tempo de resposta quando o e-mail não existe
// (evita enumeração de usuários por análise de tempo).
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 12);

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ---------------------------------------------------------------------------
// Limitação de tentativas (mitiga força bruta / credential stuffing)
// ---------------------------------------------------------------------------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { erro: 'Muitas tentativas. Tente novamente mais tarde.' },
});

// ---------------------------------------------------------------------------
// Rota
// ---------------------------------------------------------------------------
const router = express.Router();

router.post('/auth/login', loginLimiter, async (req, res) => {
  try {
    const { email, senha } = req.body || {};

    // 1. Validação de entrada
    if (
      typeof email !== 'string' ||
      typeof senha !== 'string' ||
      !EMAIL_REGEX.test(email) ||
      email.length > 254 ||
      senha.length === 0 ||
      senha.length > 128 // bcrypt só considera 72 bytes; evita payloads abusivos
    ) {
      return res.status(400).json({ erro: 'E-mail ou senha em formato inválido.' });
    }

    const emailNormalizado = email.trim().toLowerCase();

    // 2. Busca do usuário + empresa + assinatura (query parametrizada)
    const { rows } = await pool.query(
      `SELECT u.id,
              u.empresa_id,
              u.senha_hash,
              u.papel,
              u.ativo        AS usuario_ativo,
              e.ativa        AS empresa_ativa,
              a.plano,
              a.status       AS assinatura_status,
              a.expira_em
         FROM usuarios u
         JOIN empresas e         ON e.id = u.empresa_id
         LEFT JOIN assinaturas a ON a.empresa_id = e.id
                                AND a.status = 'ativa'
        WHERE u.email = $1
        ORDER BY a.expira_em DESC NULLS LAST
        LIMIT 1`,
      [emailNormalizado]
    );

    const usuario = rows[0];

    // 3. Verificação da senha (sempre executa o bcrypt, mesmo sem usuário)
    const senhaConfere = await bcrypt.compare(
      senha,
      usuario ? usuario.senha_hash : DUMMY_HASH
    );

    if (!usuario || !senhaConfere) {
      return res.status(401).json({ erro: 'Credenciais inválidas.' });
    }

    // 4. Regras de negócio (só reveladas após credenciais válidas)
    if (!usuario.usuario_ativo) {
      return res.status(403).json({ erro: 'Usuário desativado.' });
    }
    if (!usuario.empresa_ativa) {
      return res.status(403).json({ erro: 'Conta da empresa desativada.' });
    }
    const assinaturaVigente =
      usuario.assinatura_status === 'ativa' &&
      (!usuario.expira_em || new Date(usuario.expira_em) > new Date());
    if (!assinaturaVigente) {
      return res.status(402).json({ erro: 'Assinatura inativa ou expirada.' });
    }

    // 5. Emissão do token de sessão
    //    O empresaId vai no token e deve ser usado em TODAS as queries
    //    subsequentes para isolar os dados entre tenants.
    const jti = crypto.randomUUID();
    const token = jwt.sign(
      {
        sub: String(usuario.id),
        empresaId: String(usuario.empresa_id),
        papel: usuario.papel,
        plano: usuario.plano,
      },
      JWT_SECRET,
      {
        algorithm: 'HS256',
        expiresIn: JWT_TTL,
        issuer: 'saas-gestao',
        jwtid: jti,
      }
    );

    // 6. Registro de último acesso (não bloqueia a resposta em caso de falha)
    pool
      .query('UPDATE usuarios SET ultimo_login_em = NOW() WHERE id = $1', [usuario.id])
      .catch((err) => console.error('Falha ao atualizar ultimo_login_em:', err.message));

    return res.status(200).json({
      token,
      tipo: 'Bearer',
      expiraEm: JWT_TTL,
      usuario: {
        id: usuario.id,
        empresaId: usuario.empresa_id,
        papel: usuario.papel,
      },
    });
  } catch (err) {
    console.error('Erro no login:', err);
    return res.status(500).json({ erro: 'Erro interno do servidor.' });
  }
});

module.exports = router;

// ---------------------------------------------------------------------------
// Exemplo de uso no app principal:
//
//   const express = require('express');
//   const authRoutes = require('./routes/auth');
//   const app = express();
//   app.set('trust proxy', 1);          // necessário atrás de proxy/load balancer
//   app.use(express.json({ limit: '10kb' }));
//   app.use(authRoutes);
//   app.listen(3000);
// ---------------------------------------------------------------------------