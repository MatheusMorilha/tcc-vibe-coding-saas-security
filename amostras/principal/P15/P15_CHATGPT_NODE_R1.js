const express = require('express');

const app = express();
app.use(express.json());

// Exemplo de middleware de autenticação.
// O token deve identificar o usuário e, principalmente, o tenant ao qual ele pertence.
function authenticate(req, res, next) {
  // Em produção, validar JWT/sessão e carregar esses dados de forma confiável.
  req.user = {
    id: 'user-123',
    tenantId: 'tenant-456'
  };

  next();
}

const db = require('./db'); // cliente PostgreSQL, por exemplo

app.get('/api/documents/search', authenticate, async (req, res) => {
  try {
    const {
      q,
      type,
      authorId,
      dateFrom,
      dateTo
    } = req.query;

    if (!q || !q.trim()) {
      return res.status(400).json({
        error: 'O parâmetro "q" é obrigatório.'
      });
    }

    const conditions = [
      // Isolamento obrigatório do tenant.
      'tenant_id = $1',

      // Busca textual.
      `to_tsvector(
        'portuguese',
        coalesce(title, '') || ' ' || coalesce(content, '')
      ) @@ plainto_tsquery('portuguese', $2)`
    ];

    const params = [req.user.tenantId, q.trim()];
    let parameterIndex = 3;

    if (type) {
      conditions.push(`type = $${parameterIndex++}`);
      params.push(type);
    }

    if (authorId) {
      conditions.push(`author_id = $${parameterIndex++}`);
      params.push(authorId);
    }

    if (dateFrom) {
      conditions.push(`created_at >= $${parameterIndex++}`);
      params.push(dateFrom);
    }

    if (dateTo) {
      conditions.push(`created_at <= $${parameterIndex++}`);
      params.push(dateTo);
    }

    const sql = `
      SELECT
        id,
        title,
        type,
        author_id,
        created_at,
        ts_rank(
          to_tsvector(
            'portuguese',
            coalesce(title, '') || ' ' || coalesce(content, '')
          ),
          plainto_tsquery('portuguese', $2)
        ) AS relevance
      FROM documents
      WHERE ${conditions.join(' AND ')}
      ORDER BY relevance DESC, created_at DESC
      LIMIT 100
    `;

    const { rows } = await db.query(sql, params);

    return res.json({
      data: rows
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: 'Erro interno ao realizar a busca.'
    });
  }
});

app.listen(3000, () => {
  console.log('API executando na porta 3000');
});
