import { Client } from '@elastic/elasticsearch';

// Inicialização do cliente do Elasticsearch
const esClient = new Client({
  node: process.env.ELASTICSEARCH_URL || 'http://localhost:9200',
});

/**
 * Controller de busca textual em documentos
 * @param {import('fastify').FastifyRequest} request
 * @param {import('fastify').FastifyReply} reply
 */
export async function searchDocumentsHandler(request, reply){
  try {
    // 1. Extração obrigatória do Tenant ID do contexto da requisição (autenticação/JWT)
    const tenantId = request.user?.tenantId;

    if (!tenantId) {
      return reply.status(401).send({ error: 'Tenant context is missing or invalid' });
    }

    // 2. Extração dos parâmetros da query string
    const {
      q,           // Termo de busca textual
      type,        // Filtro por tipo (ex: 'invoice', 'contract', 'report')
      authorId,    // Filtro por ID do autor
      startDate,   // Data inicial (ISO 8601)
      endDate,     // Data final (ISO 8601)
      page = 1,    // Paginação
      limit = 10,  // Itens por página
    } = request.query;

    const pageNumber = Math.max(1, parseInt(page, 10));
    const limitNumber = Math.min(100, Math.max(1, parseInt(limit, 10)));
    const from = (pageNumber - 1) * limitNumber;

    // 3. Construção da query com filtros compostos (bool query)
    const mustConditions = [];
    const filterConditions = [];

    // CRÍTICO PARA MULTI-TENANCY: O filtro por tenantId é OBRIGATÓRIO e inegociável
    filterConditions.push({ term: { tenantId: tenantId } });

    // Busca textual ampla no título e no conteúdo do documento
    if (q && q.trim() !== '') {
      mustConditions.push({
        multi_match: {
          query: q.trim(),
          fields: ['title^2', 'content'], // Título tem peso 2x maior na relevância
          fuzziness: 'AUTO',             // Tolera pequenos erros de digitação
        },
      });
    } else {
      mustConditions.push({ match_all: {} });
    }

    // Filtro opcional: Tipo do documento
    if (type) {
      filterConditions.push({ term: { type: type } });
    }

    // Filtro opcional: Autor
    if (authorId) {
      filterConditions.push({ term: { authorId: authorId } });
    }

    // Filtro opcional: Intervalo de datas de criação/atualização
    if (startDate || endDate) {
      const rangeFilter = { range: { createdAt: {} } };
      if (startDate) rangeFilter.range.createdAt.gte = startDate;
      if (endDate) rangeFilter.range.createdAt.lte = endDate;
      filterConditions.push(rangeFilter);
    }

    // 4. Execução no Elasticsearch
    const response = await esClient.search({
      index: 'saas_documents',
      from,
      size: limitNumber,
      body: {
        query: {
          bool: {
            must: mustConditions,
            filter: filterConditions, // 'filter' não impacta na pontuação de relevância (score) e usa cache
          },
        },
        highlight: {
          fields: {
            title: {},
            content: { fragment_size: 150, number_of_fragments: 3 },
          },
        },
        sort: q ? [{ _score: 'desc' }, { createdAt: 'desc' }] : [{ createdAt: 'desc' }],
      },
    });

    // 5. Formatação da resposta
    const totalHits = response.hits.total.value;
    const documents = response.hits.hits.map((hit) => ({
      id: hit._id,
      ...hit._source,
      highlights: hit.highlight || null,
      score: hit._score,
    }));

    return reply.status(200).send({
      data: documents,
      meta: {
        total: totalHits,
        page: pageNumber,
        limit: limitNumber,
        totalPages: Math.ceil(totalHits / limitNumber),
      },
    });
  } catch (error) {
    request.log.error(error);
    return reply.status(500).send({ error: 'Internal server error while searching documents' });
  }
}