import express from 'express';
import { z } from 'zod';
import pg from 'pg';

const router = express.Router();
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

/**
 * Middleware simulado de autenticação e contexto multi-tenant.
 * Em produção, decodifica e valida o JWT/sessão emitida pelo IdP.
 *
 * OWASP A01: Broken Access Control:
 * O tenantId DEVE vir estritamente da identidade criptografada do usuário autenticado,
 * NUNCA de headers arbitrários, parâmetros de rota ou query strings enviados pelo cliente.
 */
function authenticateAndResolveTenant(req, res, next){
  // Exemplo de extração a partir do token decodificado
  const authUser = req.user;

  if (!authUser || !authUser.tenantId) {
    return res.status(401).json({ error: 'Não autorizado ou tenant não identificado.' });
  }

  req.tenantId = authUser.tenantId;
  next();
}

/**
 * Schema de validação dos parâmetros de consulta (Query Params).
 *
 * OWASP A03: Injection & OWASP A04: Insecure Design:
 * Sanitização e restrição de formato, tamanho de string e limites de paginação
 * para mitigar ataques de negação de serviço (DoS) e comportamentos inesperados.
 */
const listCustomersQuerySchema = z.object({
  name: z
    .string()
    .trim()
    .max(100, 'O filtro por nome deve ter no máximo 100 caracteres.')
    .regex(/^[\p{L}\p{N}\s.\-_]+$/u, 'O nome contém caracteres inválidos.')
    .optional(),
  page: z
    .coerce
    .number()
    .int()
    .positive()
    .default(1),
  limit: z
    .coerce
    .number()
    .int()
    .min(1)
    .max(100, 'O limite máximo por página é de 100 registros.')
    .default(20),
});

/**
 * Escapa metacaracteres especiais de operadores LIKE/ILIKE (%, _)
 * para evitar abuso na busca por padrões.
 */
function escapeLikeWildcards(input){
  return input.replace(/([%_\\])/g, '\\$1');
}

/**
 * Rota GET /api/v1/customers
 */
router.get('/customers', authenticateAndResolveTenant, async (req, res) => {
  // 1. Validação de Entrada (A03 / A04)
  const validation = listCustomersQuerySchema.safeParse(req.query);
  if (!validation.success) {
    return res.status(400).json({
      error: 'Parâmetros de requisição inválidos.',
      details: validation.error.flatten().fieldErrors,
    });
  }

  const { name, page, limit } = validation.data;
  const tenantId = req.tenantId;
  const offset = (page - 1) * limit;

  // 2. Construção de Consulta Parametrizada (A03: SQL Injection Prevention)
  const queryParams = [tenantId];
  let filterClause = '';

  if (name) {
    const escapedName = escapeLikeWildcards(name);
    queryParams.push(`%${escapedName}%`);
    filterClause = `AND name ILIKE $${queryParams.length} ESCAPE '\\'`;
  }

  queryParams.push(limit, offset);
  const limitParamIndex = queryParams.length - 1;
  const offsetParamIndex = queryParams.length;

  const dataQuery = `
    SELECT
      id,
      name,
      document,
      email,
      created_at
    FROM customers
    WHERE tenant_id = $1
      ${filterClause}
    ORDER BY created_at DESC
    LIMIT $${limitParamIndex} OFFSET $${offsetParamIndex};
  `;

  const countQuery = `
    SELECT COUNT(*)::int AS total
    FROM customers
    WHERE tenant_id = $1
      ${filterClause};
  `;

  try {
    // 3. Execução das queries garantindo isolamento total por tenant_id
    const [dataResult, countResult] = await Promise.all([
      pool.query(dataQuery, queryParams),
      // Para o count, usamos apenas os parâmetros até o filtro de nome (ignora limit e offset)
      pool.query(countQuery, queryParams.slice(0, name ? 2 : 1)),
    ]);

    const totalRecords = countResult.rows[0].total;

    return res.status(200).json({
      meta: {
        page,
        limit,
        totalRecords,
        totalPages: Math.ceil(totalRecords / limit),
      },
      data: dataResult.rows,
    });
  } catch (error) {
    // OWASP A09: Security Logging and Monitoring Failures:
    // Log detalhado internamente para auditoria/rastreamento sem expor dados sensíveis externamente
    console.error('[DATABASE_ERROR] Falha ao consultar clientes:', {
      tenantId,
      message: error.message,
      timestamp: new Date().toISOString(),
    });

    // Resposta sanitizada para não expor stack trace ou schema (Information Disclosure)
    return res.status(500).json({
      error: 'Ocorreu um erro interno ao processar a consulta.',
    });
  }
});

export default router;