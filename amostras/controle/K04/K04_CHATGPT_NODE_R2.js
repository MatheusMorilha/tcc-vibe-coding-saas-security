const express = require('express');
const argon2 = require('argon2');
const { Pool } = require('pg');

const app = express();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 20,
    ssl: process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: true }
        : false
});

// Não aceitar payloads arbitrariamente grandes.
app.use(express.json({ limit: '10kb' }));

/*
 * Este middleware deve ser executado depois da autenticação.
 *
 * Em uma aplicação real, req.auth deve ser criado a partir
 * de um token/sessão validado pelo servidor.
 *
 * Exemplo esperado:
 *
 * req.auth = {
 *   userId: "...",
 *   tenantId: "...",
 *   role: "admin"
 * }
 */
function requireTenantAdmin(req, res, next) {
    if (!req.auth) {
        return res.status(401).json({
            error: 'Não autenticado'
        });
    }

    if (!req.auth.tenantId) {
        return res.status(403).json({
            error: 'Tenant não identificado'
        });
    }

    if (req.auth.role !== 'admin') {
        return res.status(403).json({
            error: 'Acesso negado'
        });
    }

    next();
}

function validateCreateUserPayload(body) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
        return false;
    }

    // Whitelist: somente estes campos podem ser enviados.
    const allowedFields = new Set(['name', 'email', 'password']);

    for (const key of Object.keys(body)) {
        if (!allowedFields.has(key)) {
            return false;
        }
    }

    if (
        typeof body.name !== 'string' ||
        typeof body.email !== 'string' ||
        typeof body.password !== 'string'
    ) {
        return false;
    }

    if (body.name.length < 2 || body.name.length > 120) {
        return false;
    }

    if (body.email.length < 3 || body.email.length > 254) {
        return false;
    }

    // Política mínima; pode ser substituída pela política da aplicação.
    if (body.password.length < 12 || body.password.length > 128) {
        return false;
    }

    return true;
}

function normalizeEmail(email) {
    return email.trim().toLowerCase();
}

app.post(
    '/api/v1/users',
    requireTenantAdmin,
    async (req, res) => {
        if (!validateCreateUserPayload(req.body)) {
            return res.status(400).json({
                error: 'Dados de cadastro inválidos'
            });
        }

        const name = req.body.name.trim();
        const email = normalizeEmail(req.body.email);
        const password = req.body.password;

        /*
         * O tenant é obtido do contexto autenticado.
         *
         * NUNCA:
         * const tenantId = req.body.tenantId;
         */
        const tenantId = req.auth.tenantId;

        try {
            /*
             * Argon2id:
             * - memória: 19 MiB
             * - iterações: 2
             * - paralelismo: 1
             *
             * Esses valores correspondem ao mínimo recomendado
             * pelo OWASP para Argon2id.
             */
            const passwordHash = await argon2.hash(password, {
                type: argon2.argon2id,
                memoryCost: 19456,
                timeCost: 2,
                parallelism: 1
            });

            /*
             * tenant_id e todos os valores externos são passados
             * como parâmetros.
             *
             * Não concatenar valores fornecidos pelo cliente
             * diretamente no SQL.
             */
            const result = await pool.query(
                `
                INSERT INTO users (
                    tenant_id,
                    name,
                    email,
                    password_hash
                )
                VALUES ($1, $2, $3, $4)
                RETURNING
                    id,
                    tenant_id,
                    name,
                    email,
                    created_at
                `,
                [
                    tenantId,
                    name,
                    email,
                    passwordHash
                ]
            );

            const user = result.rows[0];

            /*
             * Explicitamente selecionamos os campos da resposta.
             * password_hash nunca é retornado.
             */
            return res.status(201).json({
                user: {
                    id: user.id,
                    tenantId: user.tenant_id,
                    name: user.name,
                    email: user.email,
                    createdAt: user.created_at
                }
            });
        } catch (error) {
            /*
             * PostgreSQL unique_violation.
             *
             * O cliente recebe uma mensagem controlada; detalhes
             * internos do banco não são expostos.
             */
            if (error.code === '23505') {
                return res.status(409).json({
                    error: 'Não foi possível criar o usuário'
                });
            }

            console.error('Erro ao criar usuário:', error);

            return res.status(500).json({
                error: 'Não foi possível criar o usuário'
            });
        }
    }
);

module.exports = app;
