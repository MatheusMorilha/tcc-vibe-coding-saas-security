const http = require('node:http');
const crypto = require('node:crypto');

const {Pool }= require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// PATCH /api/users/:userId/permissions
async function updateUserPermissions(req, res, userId) {
  const tenantId = req.auth.tenantId;
  const actorUserId = req.auth.userId;

  let body;

  try {
    body= await readJsonBody(req);
  }catch {
    return sendJson(res, 400, { error: 'JSON inválido' });
  }

  if (!Array.isArray(body.permissions)) {
    return sendJson(res, 400, {
      error: 'permissions deve ser um array'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    /*
     * O tenant_id participa da consulta.
     * Isso impede que um usuário de uma empresa altere
     * um usuário pertencente a outro tenant.
     */
    const userResult = await client.query(
      `
      SELECT id, tenant_id, permissions
      FROM users
      WHERE id = $1
        AND tenant_id = $2
      FOR UPDATE
      `,
      [userId, tenantId]
    );

    if (userResult.rowCount=== 0) {
      await client.query('ROLLBACK');

      return sendJson(res, 404, {
        error: 'Usuário não encontrado'
      });
    }

    const user = userResult.rows[0];

    const oldPermissions = user.permissions|| [];
    const newPermissions = [...new Set(body.permissions)];

    await client.query(
      `
      UPDATE users
      SET permissions = $1,
          updated_at = NOW()
      WHERE id = $2
        AND tenant_id = $3
      `,
      [JSON.stringify(newPermissions), userId, tenantId]
    );

    /*
     * A auditoria fica na mesma transação da alteração.
     * Assim, não existe alteração de permissão sem seu registro
     * correspondente na trilha de auditoria.
     */
    const auditId = crypto.randomUUID();

    await client.query(
      `
      INSERT INTO audit_logs (
        id,
        tenant_id,
        actor_user_id,
        action,
        resource_type,
        resource_id,
        before_data,
        after_data,
        created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
      `,
      [
        auditId,
        tenantId,
        actorUserId,
        'USER_PERMISSIONS_UPDATED',
        'user',
        userId,
        JSON.stringify({ permissions: oldPermissions }),
        JSON.stringify({ permissions: newPermissions })
      ]
    );

    await client.query('COMMIT');

    return sendJson(res, 200, {
      userId,
      permissions: newPermissions,
      auditId
    });
  }catch (error) {
    await client.query('ROLLBACK');
    console.error(error);

    return sendJson(res, 500, {
      error: 'Não foi possível alterar as permissões'
    });
  }finally {
    client.release();
  }
}

// GET /api/audit-logs?resourceType=user&resourceId=...
async function getAuditLogs(req, res) {
  const tenantId = req.auth.tenantId;
  const url = new URL(req.url, 'http://localhost');

  const resourceType = url.searchParams.get('resourceType');
  const resourceId = url.searchParams.get('resourceId');

  const values = [tenantId];
  const conditions = ['tenant_id = $1'];

  if (resourceType) {
    values.push(resourceType);
    conditions.push(`resource_type = $${values.length}`);
  }

  if (resourceId) {
    values.push(resourceId);
    conditions.push(`resource_id = $${values.length}`);
  }

  const result = await pool.query(
    `
    SELECT
      id,
      actor_user_id,
      action,
      resource_type,
      resource_id,
      before_data,
      after_data,
      created_at
    FROM audit_logs
    WHERE${conditions.join(' AND ')}
    ORDER BY created_at DESC
    LIMIT 100
    `,
    values
  );

  return sendJson(res, 200, {
    data: result.rows
  });
}

function readJsonBody(req) {
  return new Promise((resolve, reject)=> {
    let data= '';

    req.on('data', chunk=> {
      data+= chunk;

      if (data.length > 1024 * 1024) {
        reject(new Error('Payload muito grande'));
        req.destroy();
      }
    });

    req.on('end', ()=> {
      try {
        resolve(JSON.parse(data|| '{}'));
      }catch {
        reject(new Error('JSON inválido'));
      }
    });

    req.on('error', reject);
  });
}

function sendJson(res, statusCode, body) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json'
  });

  res.end(JSON.stringify(body));
}