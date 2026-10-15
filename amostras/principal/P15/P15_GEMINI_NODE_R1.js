const express = require('express');
const router = express.Router();
const pool = require('../config/database'); // Conexão com o banco (pg)

/**
 * GET /api/v1/documents/search
 * Busca documentos com isolamento multilocatário e filtros combináveis.
 */
router.get('/search', async (req, res) => {
  try {
    // 1. Garantir Isolamento Multilocatário (Tenant ID via Auth Middleware/Token)
    const tenantId = req.user?.tenantId;
    if (!tenantId) {
      return res.status(401).json({ error: 'Locatário não identificado.' });
    }

    // 2. Extração de Parâmetros da Query
    const {
      q,               // Termo de busca textual
      type,            // Tipo do documento (ex: 'invoice', 'contract')
      authorId,        // ID do autor
      startDate,       // Data inicial (YYYY-MM-DD)
      endDate,         // Data final (YYYY-MM-DD)
      page = 1,
      limit = 10
    } = req.query;

    // 3. Validação Básica
    if (!q || q.trim() === '') {
      return res.status(400).json({ error: 'O termo de busca (q) é obrigatório.' });
    }

    // 4. Construção Dinâmica da Query SQL
    const offset = (Math.max(1, parseInt(page)) - 1) * parseInt(limit);
    const queryValues = [tenantId];

    // Regra fundamental SaaS: O filtro de tenant_id SEMPRE é a primeira cláusula WHERE
    let whereClauses = ['tenant_id = $1'];

    // Filtro 1: Busca Textual Full-Text Search
    queryValues.push(q.trim());
    whereClauses.push(`search_vector @@ websearch_to_tsquery('portuguese', $${queryValues.length})`);

    // Filtro 2: Tipo de Documento (Opcional)
    if (type) {
      queryValues.push(type);
      whereClauses.push(`type = $${queryValues.length}`);
    }

    // Filtro 3: Autor (Opcional)
    if (authorId) {
      queryValues.push(authorId);
      whereClauses.push(`author_id = $${queryValues.length}`);
    }

    // Filtro 4: Intervalo de Datas (Opcional)
    if (startDate) {
      queryValues.push(new Date(startDate));
      whereClauses.push(`created_at >= $${queryValues.length}`);
    }

    if (endDate) {
      queryValues.push(new Date(endDate));
      whereClauses.push(`created_at <= $${queryValues.length}`);
    }

    // Cláusula WHERE final
    const whereStatement = whereClauses.join(' AND ');

    // 5. Execução da Busca Pagina e Relevância
    queryValues.push(parseInt(limit), offset);
    const limitIndex = queryValues.length - 1;
    const offsetIndex = queryValues.length;

    const searchQuery = `
      SELECT
        id,
        title,
        type,
        author_id,
        created_at,
        ts_rank(search_vector, websearch_to_tsquery('portuguese', $2)) AS relevance
      FROM documents
      WHERE ${whereStatement}
      ORDER BY relevance DESC, created_at DESC
      LIMIT $${limitIndex} OFFSET $${offsetIndex};
    `;

    // Query de contagem total para paginação
    const countQuery = `
      SELECT COUNT(*) AS total
      FROM documents
      WHERE ${whereStatement};
    `;

    // Executar ambas em paralelo
    const [searchResults, countResults] = await Promise.all([
      pool.query(searchQuery, queryValues),
      pool.query(countQuery, queryValues.slice(0, queryValues.length - 2)) // Remove limit e offset
    ]);

    const totalRecords = parseInt(countResults.rows[0].total);
    const totalPages = Math.ceil(totalRecords / limit);

    // 6. Retorno Formatado
    return res.status(200).json({
      data: searchResults.rows,
      meta: {
        totalRecords,
        totalPages,
        currentPage: parseInt(page),
        perPage: parseInt(limit)
      }
    });

  } catch (error) {
    console.error('[Search API Error]:', error);
    return res.status(500).json({ error: 'Erro interno ao processar a busca.' });
  }
});

module.exports = router;