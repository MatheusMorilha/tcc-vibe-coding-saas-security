'use strict';

const express = require('express');
const helmet = require('helmet');
const crypto = require('crypto');
const argon2 = require('argon2');
const { Pool } = require('pg');

const app = express();

app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({
    limit: '10kb'
}));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: true }
        : false
});

const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

/*
 * Gere uma sessão usando CSPRNG.
 *
 * 32 bytes = 256 bits de entropia.
 */
function generateSessionToken() {
    return crypto.randomBytes(32).toString('base64url');
}

/*
 * O token bruto nunca é persistido no banco.
 * Apenas seu SHA-256 é armazenado.
 */
function hashSessionToken(token) {
    return crypto
        .createHash('sha256')
        .update(token)
        .digest();
}

function normalizeEmail(email) {
    return email.trim().toLowerCase();
}

function isValidEmail(email) {
    // Validação deliberadamente simples:
    // a validação definitiva deve ocorrer também
    // conforme as regras da aplicação.
    return (
        typeof email === 'string' &&
        email.length <= 254 &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    );
}

/*
 * Exemplo de limite local.
 *
 * Em produção, o contador deve ficar em Redis ou
 * outro armazenamento compartilhado para funcionar
 * corretamente com múltiplas instâncias da API.
 */
const failedAttempts = new Map();

function checkRateLimit(key) {
    const now = Date.now();
    const entry = failedAttempts.get(key);

    if (!entry || entry.resetAt <= now) {
        return true;
    }

    return entry.count < 10;
}

function registerFailedAttempt(key) {
    const now = Date.now();
    const entry = failedAttempts.get(key);

    if (!entry || entry.resetAt <= now) {
        failedAttempts.set(key, {
            count: 1,
            resetAt: now + 15 * 60 * 1000
        });

        return;
    }

    entry.count += 1;
}

function clearFailedAttempts(key) {
    failedAttempts.delete(key);
}

/*
 * POST /api/auth/login
 *
 * Body:
 * {
 *   "email": "usuario@empresa.com",
 *   "password": "senha"
 * }
 */
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body || {};

    if (
        typeof email !== 'string' ||
        typeof password !== 'string' ||
        !isValidEmail(email) ||
        password.length === 0 ||
        password.length > 1024
    ) {
        return res.status(400).json({
            error: 'Invalid request'
        });
    }

    const normalizedEmail = normalizeEmail(email);

    /*
     * A chave combina IP + identidade para dificultar
     * brute force sem bloquear completamente um usuário
     * legítimo por ataques contra outro usuário.
     */
    const ip = req.ip || 'unknown';
    const rateLimitKey = `${ip}:${normalizedEmail}`;

    if (!checkRateLimit(rateLimitKey)) {
        return res.status(429).json({
            error: 'Too many authentication attempts'
        });
    }

    const client = await pool.connect();

    try {
        /*
         * A busca recupera o usuário e o tenant em uma única
         * consulta. O tenant_id fica associado à sessão criada.
         */
        const result = await client.query(
            `
            SELECT
                u.id AS user_id,
                u.tenant_id,
                u.password_hash,
                u.status AS user_status,
                t.subscription_status
            FROM users u
            INNER JOIN tenants t
                ON t.id = u.tenant_id
            WHERE u.email = $1
            LIMIT 1
            `,
            [normalizedEmail]
        );

        /*
         * Não diferenciamos:
         *
         * - usuário inexistente
         * - senha incorreta
         * - usuário/assinatura indisponível
         *
         * Isso evita um oracle de autenticação/account enumeration.
         */
        if (result.rowCount !== 1) {
            registerFailedAttempt(rateLimitKey);

            return res.status(401).json({
                error: 'Invalid credentials'
            });
        }

        const user = result.rows[0];

        let passwordValid = false;

        try {
            passwordValid = await argon2.verify(
                user.password_hash,
                password
            );
        } catch (error) {
            /*
             * Não expor detalhes do erro de Argon2 ao cliente.
             */
            console.error('Password verification error:', error);
        }

        if (!passwordValid) {
            registerFailedAttempt(rateLimitKey);

            return res.status(401).json({
                error: 'Invalid credentials'
            });
        }

        /*
         * Depois que a senha está correta, verificamos
         * o estado do usuário e da assinatura.
         */
        if (
            user.user_status !== 'active' ||
            user.subscription_status !== 'active'
        ) {
            registerFailedAttempt(rateLimitKey);

            /*
             * Mantemos uma resposta genérica para não revelar
             * informações desnecessárias sobre a conta.
             */
            return res.status(401).json({
                error: 'Invalid credentials'
            });
        }

        const rawToken = generateSessionToken();
        const tokenHash = hashSessionToken(rawToken);

        const expiresAt = new Date(
            Date.now() + SESSION_TTL_MS
        );

        await client.query('BEGIN');

        /*
         * tenant_id é gravado na sessão.
         *
         * Assim, os middlewares subsequentes podem derivar
         * o contexto de tenant exclusivamente da sessão
         * autenticada, e não de um tenant_id enviado pelo cliente.
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

        await client.query('COMMIT');

        clearFailedAttempts(rateLimitKey);

        /*
         * O token fica em cookie:
         *
         * HttpOnly -> JavaScript do navegador não consegue lê-lo.
         * Secure   -> enviado somente via HTTPS.
         * SameSite -> reduz ataques CSRF.
         *
         * O token NÃO aparece na URL.
         */
        res.cookie('session', rawToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            expires: expiresAt,
            path: '/'
        });

        return res.status(200).json({
            authenticated: true
        });

    } catch (error) {
        await client.query('ROLLBACK');

        console.error('Authentication error:', error);

        /*
         * Não retornar stack trace, SQL ou detalhes internos.
         */
        return res.status(500).json({
            error: 'Internal server error'
        });

    } finally {
        client.release();
    }
});
