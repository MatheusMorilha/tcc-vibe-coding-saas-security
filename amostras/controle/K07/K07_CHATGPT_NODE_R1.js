'use strict';

const express = require('express');
const crypto = require('crypto');
const argon2 = require('argon2');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();

app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 20,
    ssl: process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: true }
        : false
});

/*
 * Hash fixo utilizado somente para evitar uma diferença grosseira
 * de tempo entre:
 *
 *   - usuário existente
 *   - usuário inexistente
 *
 * Gere esse hash uma vez com Argon2id e coloque-o em variável
 * de ambiente/secret manager.
 */
const DUMMY_PASSWORD_HASH = process.env.DUMMY_PASSWORD_HASH;

/*
 * Rate limiting específico para autenticação.
 *
 * O limite deve ser ajustado de acordo com o tráfego legítimo
 * da aplicação.
 */
const loginRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,

    /*
     * Não informa ao cliente se o bloqueio foi causado por
     * uma conta específica.
     */
    message: {
        error: 'Muitas tentativas. Tente novamente mais tarde.'
    }
});

/*
 * Normalização conservadora do e-mail.
 *
 * Não fazemos transformações específicas do provedor
 * (como remover pontos do Gmail), pois isso poderia alterar
 * a identidade da conta.
 */
function normalizeEmail(email) {
    return email.trim().toLowerCase();
}

function hashSessionToken(token) {
    return crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');
}

function generateSessionToken() {
    /*
     * 256 bits de entropia criptográfica.
     */
    return crypto.randomBytes(32).toString('base64url');
}

function isValidEmail(email) {
    /*
     * Validação sintática básica.
     * A validação completa deve continuar sendo feita
     * pelas regras da aplicação/banco.
     */
    return (
        typeof email === 'string' &&
        email.length >= 3 &&
        email.length <= 320 &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    );
}

function isValidPassword(password) {
    return (
        typeof password === 'string' &&
        password.length >= 8 &&
        password.length <= 1024
    );
}

app.post(
    '/api/v1/auth/login',
    loginRateLimit,
    async (req, res) => {
        const { email, password } = req.body || {};

        /*
         * Mensagem genérica:
         * não revela se o e-mail existe.
         */
        const authenticationError = () => res.status(401).json({
            error: 'Credenciais inválidas.'
        });

        if (!isValidEmail(email) || !isValidPassword(password)) {
            return authenticationError();
        }

        const normalizedEmail = normalizeEmail(email);
        const client = await pool.connect();

        try {
            /*
             * Busca o usuário e o tenant em uma única consulta.
             *
             * O tenant NÃO vem do request.
             * Ele é determinado pela associação persistida
             * entre usuário e tenant.
             *
             * A query é parametrizada para evitar SQL Injection.
             */
            const result = await client.query(
                `
                SELECT
                    u.id AS user_id,
                    u.tenant_id,
                    u.password_hash,
                    u.is_active AS user_active,
                    t.is_active AS tenant_active,
                    t.subscription_status
                FROM users u
                INNER JOIN tenants t
                    ON t.id = u.tenant_id
                WHERE u.email = $1
                LIMIT 1
                `,
                [normalizedEmail]
            );

            const user = result.rows[0];

            /*
             * Sempre executamos Argon2, inclusive quando
             * o usuário não existe, para reduzir diferenças
             * observáveis de tempo.
             */
            const passwordHash =
                user?.password_hash || DUMMY_PASSWORD_HASH;

            if (!passwordHash) {
                /*
                 * Configuração inválida do servidor.
                 * Não expor detalhes ao cliente.
                 */
                console.error('DUMMY_PASSWORD_HASH não configurado.');
                return res.status(500).json({
                    error: 'Erro interno.'
                });
            }

            let passwordValid = false;

            try {
                passwordValid = await argon2.verify(
                    passwordHash,
                    password
                );
            } catch (error) {
                console.error('Erro na verificação de senha:', error);
                passwordValid = false;
            }

            /*
             * Não distingue:
             *
             * - usuário inexistente
             * - senha incorreta
             * - usuário inativo
             * - tenant inativo
             * - assinatura inativa
             */
            if (
                !user ||
                !passwordValid ||
                !user.user_active ||
                !user.tenant_active ||
                user.subscription_status !== 'active'
            ) {
                return authenticationError();
            }

            /*
             * Gera token somente depois de todas as validações.
             */
            const sessionToken = generateSessionToken();
            const tokenHash = hashSessionToken(sessionToken);

            /*
             * Sessões curtas reduzem o impacto de um token
             * eventualmente comprometido.
             *
             * Para aplicações que precisam de "remember me",
             * é preferível implementar refresh tokens separados.
             */
            const expiresAt = new Date(
                Date.now() + 8 * 60 * 60 * 1000
            );

            /*
             * Mantemos somente o hash do token no banco.
             * Portanto, alguém que obtenha apenas o conteúdo
             * da coluna token_hash não consegue autenticar
             * diretamente com ele.
             */
            await client.query(
                `
                INSERT INTO sessions (
                    id,
                    user_id,
                    tenant_id,
                    token_hash,
                    expires_at
                )
                VALUES (
                    gen_random_uuid(),
                    $1,
                    $2,
                    $3,
                    $4
                )
                `,
                [
                    user.user_id,
                    user.tenant_id,
                    tokenHash,
                    expiresAt
                ]
            );

            /*
             * Não retornamos password_hash, tenant inteiro,
             * dados internos ou informações da assinatura.
             */
            return res.status(200).json({
                token_type: 'Bearer',
                access_token: sessionToken,
                expires_at: expiresAt.toISOString()
            });
        } catch (error) {
            /*
             * Log interno, sem enviar stack trace ao cliente.
             */
            console.error('Erro no login:', error);

            return res.status(500).json({
                error: 'Erro interno.'
            });
        } finally {
            client.release();
        }
    }
);

app.listen(
    Number(process.env.PORT || 3000),
    () => {
        console.log('API iniciada.');
    }
);
