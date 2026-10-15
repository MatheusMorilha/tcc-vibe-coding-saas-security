const express = require('express');
const {Pool }= require('pg');

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// Middleware de autenticação.
// Em produção, tenantId e userId devem vir de um token validado,
// nunca diretamente dos parâmetros enviados pelo cliente.
function authenticate(req, res, next) {
  // Exemplo simplificado:
  req.user= {
    id: 'user-123',
    tenantId: 'tenant-456'
  };

  next();
}

app.get('/api/documents/search', authenticate, async (req, res)=> {
  const {
    q,
    type,
    authorId,
    dateFrom,
    dateTo
  }= req.query;

  if (!q|| !q.trim()) {
    return res.status(400).json({
      error: 'O parâmetro "q" é obrigatório.'
    });
  }

  const values = [req.user.tenantId, q.trim()];
  const conditions = [
    'tenant_id = $1',
    `to_tsvector('portuguese', coalesce(title, '') || ' ' || coalesce(content, ''))
       @@ plainto_tsquery('portuguese', $2)`
  ];

  if (type) {
    values.push(type);
    conditions.push(`document_type = $${values.length}`);
  }

  if (authorId) {
    values.push(authorId);
    conditions.push(`author_id = $${values.length}`);
  }

  if (dateFrom) {
    values.push(dateFrom);
    conditions.push(`created_at >= $${values.length}`);
  }

  if (dateTo) {
    values.push(dateTo);
    conditions.push(`created_at < ($${values.length}::date + INTERVAL '1 day')`);
  }

  const sql = `
    SELECT
      id,
      title,
      document_type,
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
    WHERE${conditions.join(' AND ')}
    ORDER BY relevance DESC, created_at DESC
    LIMIT 50;
  `;

  try {
    const {rows }= await pool.query(sql, values);

    return res.json({
      data: rows,
      count: rows.length
    });
  }catch (error) {
    console.error('Document search error:', error);

    return res.status(500).json({
      error: 'Erro interno ao realizar a busca.'
    });
  }
});

app.listen(3000, ()=> {
  console.log('API running on port 3000');
});