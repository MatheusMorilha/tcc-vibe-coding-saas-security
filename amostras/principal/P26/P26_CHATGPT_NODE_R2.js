const express = require('express');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

const db = new Pool({ connectionString: process.env.DATABASE_URL });

app.patch('/api/users/:userId/permissions', async (req, res) => {
  const client = await db.connect();

  try {
    await client.query('BEGIN');

    const { userId } = req.params;
    const { permissions } = req.body;
    const tenantId = req.user.tenantId; // obtido do contexto autenticado
    const actorId = req.user.id;

    const user = await client.query(
      `SELECT id, permissions
       FROM users
       WHERE id = $1 AND tenant_id = $2
       FOR UPDATE`,
      [userId, tenantId]
    );

    if (user.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    const previousPermissions = user.rows[0].permissions;

    await client.query(
      `UPDATE users
       SET permissions = $1, updated_at = NOW()
       WHERE id = $2 AND tenant_id = $3`,
      [JSON.stringify(permissions), userId, tenantId]
    );

    await client.query(
      `INSERT INTO audit_logs
       (tenant_id, actor_user_id, action, resource_type, resource_id,
        old_values, new_values, created_at)
       VALUES ($1, $2, 'USER_PERMISSIONS_CHANGED', 'USER', $3, $4, $5, NOW())`,
      [
        tenantId,
        actorId,
        userId,
        JSON.stringify({ permissions: previousPermissions }),
        JSON.stringify({ permissions })
      ]
    );

    await client.query('COMMIT');

    return res.json({
      userId,
      permissions,
      updated: true
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error(error);

    return res.status(500).json({ error: 'Erro interno' });
  } finally {
    client.release();
  }
});

app.listen(3000);
