const express = require("express");
const {Pool }= require("pg");

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// Exemplo: autenticação já validada pelo middleware.
// req.auth contém o usuário autenticado e sua empresa.
function requireAuth(req, res, next) {
  // Em produção, substituir por JWT/session middleware.
  req.auth= {
    userId: req.headers["x-user-id"],
    tenantId: req.headers["x-tenant-id"]
  };

  if (!req.auth.userId|| !req.auth.tenantId) {
    return res.status(401).json({ error: "Não autenticado" });
  }

  next();
}

/*
  PATCH /api/users/:userId/permissions

  Body:
  {
    "permissions": [
      "users.read",
      "users.write",
      "reports.read"
    ]
  }
*/
app.patch(
  "/api/users/:userId/permissions",
  requireAuth,
  async (req, res)=> {
    const client = await pool.connect();

    try {
      const targetUserId = req.params.userId;
      const tenantId = req.auth.tenantId;
      const actorUserId = req.auth.userId;
      const {permissions }= req.body;

      if (!Array.isArray(permissions)) {
        return res.status(400).json({
          error: "permissions deve ser um array"
        });
      }

      if (!permissions.every(p=> typeof p=== "string")) {
        return res.status(400).json({
          error: "Todas as permissões devem ser strings"
        });
      }

      await client.query("BEGIN");

      /*
       * O tenant_id faz parte de TODAS as consultas relacionadas
       * ao usuário. Isso impede que um usuário de uma empresa
       * altere permissões de outra empresa.
       */
      const userResult = await client.query(
        `
        SELECT id, permissions
        FROM users
        WHERE id = $1
          AND tenant_id = $2
        FOR UPDATE
        `,
        [targetUserId, tenantId]
      );

      if (userResult.rowCount=== 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Usuário não encontrado"
        });
      }

      const oldPermissions = userResult.rows[0].permissions|| [];

      // Opcional: validar as permissões contra um catálogo permitido.
      const allowedResult = await client.query(
        `
        SELECT permission
        FROM available_permissions
        WHERE permission = ANY($1::text[])
        `,
        [permissions]
      );

      if (allowedResult.rowCount!== permissions.length) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error: "Uma ou mais permissões são inválidas"
        });
      }

      await client.query(
        `
        UPDATE users
        SET permissions = $1,
            updated_at = NOW()
        WHERE id = $2
          AND tenant_id = $3
        `,
        [permissions, targetUserId, tenantId]
      );

      /*
       * A auditoria ocorre na MESMA transação da alteração.
       * Assim, não existe alteração de permissão confirmada
       * sem o respectivo registro de auditoria.
       */
      await client.query(
        `
        INSERT INTO audit_log (
          tenant_id,
          actor_user_id,
          action,
          resource_type,
          resource_id,
          before_data,
          after_data,
          created_at
        )
        VALUES (
          $1,
          $2,
          'USER_PERMISSIONS_CHANGED',
          'user',
          $3,
          $4::jsonb,
          $5::jsonb,
          NOW()
        )
        `,
        [
          tenantId,
          actorUserId,
          targetUserId,
          JSON.stringify({ permissions: oldPermissions }),
          JSON.stringify({ permissions })
        ]
      );

      await client.query("COMMIT");

      return res.status(200).json({
        userId: targetUserId,
        permissions
      });
    }catch (error) {
      await client.query("ROLLBACK");

      console.error(error);

      return res.status(500).json({
        error: "Erro interno ao alterar permissões"
      });
    }finally {
      client.release();
    }
  }
);

/*
 * Consulta da trilha de auditoria.
 * Também filtrada obrigatoriamente pelo tenant_id.
 */
app.get(
  "/api/audit/users/:userId",
  requireAuth,
  async (req, res)=> {
    try {
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
        FROM audit_log
        WHERE tenant_id = $1
          AND resource_type = 'user'
          AND resource_id = $2
        ORDER BY created_at DESC
        `,
        [req.auth.tenantId, req.params.userId]
      );

      return res.json(result.rows);
    }catch (error) {
      console.error(error);

      return res.status(500).json({
        error: "Erro interno ao consultar auditoria"
      });
    }
  }
);

app.listen(3000, ()=> {
  console.log("API executando na porta 3000");
});