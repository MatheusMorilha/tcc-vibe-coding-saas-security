'use strict';

/**
 * Middleware de CORS para a API pública da plataforma SaaS multilocatária.
 *
 * Objetivos:
 *  - Permitir que aplicações web hospedadas em outros domínios consumam a API
 *    enviando credenciais de sessão (cookies) -> Access-Control-Allow-Credentials: true.
 *  - Como credenciais estão habilitadas, NUNCA usar "*" e NUNCA refletir qualquer
 *    Origin às cegas: a origem só é aceita se estiver registrada (allowlist).
 *  - Origens autorizadas = origens fixas da plataforma + origens cadastradas
 *    pelas empresas clientes (tabela compartilhada, filtrada por assinatura ativa).
 *
 * Sem dependências externas. Compatível com Express (ou qualquer framework
 * que use a assinatura (req, res, next)).
 */

const METODOS_SEGUROS = new Set(['GET', 'HEAD', 'OPTIONS']);

const PADRAO = {
  metodosPermitidos: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  cabecalhosPermitidos: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'X-CSRF-Token',
    'Idempotency-Key',
  ],
  cabecalhosExpostos: [
    'X-Request-Id',
    'X-RateLimit-Limit',
    'X-RateLimit-Remaining',
    'X-RateLimit-Reset',
    'Retry-After',
  ],
  maxAgePreflightSegundos: 600, // 10 min
  ttlCacheMs: 60_000, // origem positiva
  ttlCacheNegativoMs: 15_000, // origem negada (curto, para refletir cadastros novos)
  tamanhoMaximoCache: 5_000, // evita crescimento ilimitado por origens aleatórias
};

/**
 * Normaliza uma origem no formato canônico "esquema://host[:porta]".
 * Retorna null se for inválida, "null" (sandbox/file://) ou não for http(s).
 */
function normalizarOrigem(valor) {
  if (typeof valor !== 'string' || valor.length === 0 || valor.length > 255) return null;
  if (valor === 'null') return null;

  let url;
  try {
    url = new URL(valor);
  } catch {
    return null;
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  // Origin legítimo não tem caminho, query, hash nem credenciais embutidas.
  if (url.username || url.password) return null;
  if (url.pathname !== '/' || url.search || url.hash) return null;

  return url.origin.toLowerCase(); // URL.origin já omite portas padrão
}

/** Cache TTL simples com limite de tamanho (descarta o mais antigo). */
class CacheTTL {
  constructor(maximo) {
    this.maximo = maximo;
    this.mapa = new Map();
  }
  get(chave) {
    const item = this.mapa.get(chave);
    if (!item) return undefined;
    if (item.expiraEm <= Date.now()) {
      this.mapa.delete(chave);
      return undefined;
    }
    return item.valor;
  }
  set(chave, valor, ttlMs) {
    if (this.mapa.size >= this.maximo) {
      this.mapa.delete(this.mapa.keys().next().value);
    }
    this.mapa.set(chave, { valor, expiraEm: Date.now() + ttlMs });
  }
  limpar() {
    this.mapa.clear();
  }
}

/**
 * @param {object}   opcoes
 * @param {string[]} [opcoes.origensFixas]
 *        Origens sempre permitidas (front-end oficial, painel admin e o próprio
 *        domínio da API, necessário para chamadas same-origin com header Origin).
 * @param {(origem: string) => Promise<boolean>} opcoes.origemCadastrada
 *        Consulta à base compartilhada: retorna true se a origem foi cadastrada
 *        por alguma empresa cliente com assinatura ATIVA e a origem verificada.
 *        Exemplo SQL:
 *          SELECT 1
 *            FROM tenant_allowed_origins o
 *            JOIN tenants t       ON t.id = o.tenant_id
 *            JOIN subscriptions s ON s.tenant_id = t.id
 *           WHERE o.origin = $1 AND o.verified = true
 *             AND t.status = 'active' AND s.status = 'active'
 *           LIMIT 1
 * @param {boolean}  [opcoes.rejeitarOrigemNaoPermitida=true]
 *        Para métodos que alteram estado, responde 403 quando o Origin não é
 *        autorizado (defesa em profundidade contra CSRF, pois o CORS sozinho
 *        não impede que a requisição chegue ao servidor).
 * @param {(erro: Error) => void} [opcoes.aoErro] Hook de log/telemetria.
 */
function criarMiddlewareCors(opcoes = {}) {
  const config = { ...PADRAO, ...opcoes };

  if (typeof config.origemCadastrada !== 'function') {
    throw new Error('criarMiddlewareCors: "origemCadastrada" é obrigatório.');
  }

  const rejeitar = config.rejeitarOrigemNaoPermitida !== false;
  const aoErro = typeof config.aoErro === 'function' ? config.aoErro : () => {};

  const fixas = new Set(
    (config.origensFixas || []).map(normalizarOrigem).filter(Boolean)
  );

  const cache = new CacheTTL(config.tamanhoMaximoCache);
  // Evita N consultas simultâneas ao banco para a mesma origem.
  const emVoo = new Map();

  const valorMetodos = config.metodosPermitidos.join(', ');
  const valorExpostos = config.cabecalhosExpostos.join(', ');
  const permitidosMinusculos = new Set(
    config.cabecalhosPermitidos.map((h) => h.toLowerCase())
  );
  const valorMaxAge = String(config.maxAgePreflightSegundos);

  async function origemAutorizada(origem) {
    if (fixas.has(origem)) return true;

    const emCache = cache.get(origem);
    if (emCache !== undefined) return emCache;

    if (emVoo.has(origem)) return emVoo.get(origem);

    const consulta = (async () => {
      try {
        const ok = Boolean(await config.origemCadastrada(origem));
        cache.set(origem, ok, ok ? config.ttlCacheMs : config.ttlCacheNegativoMs);
        return ok;
      } catch (erro) {
        aoErro(erro);
        return false; // fail-closed: na dúvida, nega
      } finally {
        emVoo.delete(origem);
      }
    })();

    emVoo.set(origem, consulta);
    return consulta;
  }

  /** Aceita apenas cabeçalhos da allowlist no preflight. */
  function cabecalhosSolicitadosValidos(solicitados) {
    if (!solicitados) return true;
    return solicitados
      .split(',')
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean)
      .every((h) => permitidosMinusculos.has(h));
  }

  function adicionarVary(res, valor) {
    const atual = res.getHeader('Vary');
    if (!atual) return res.setHeader('Vary', valor);
    const lista = String(atual).split(',').map((v) => v.trim().toLowerCase());
    if (!lista.includes(valor.toLowerCase())) {
      res.setHeader('Vary', `${atual}, ${valor}`);
    }
  }

  return async function corsMiddleware(req, res, next) {
    // Respostas variam por Origin: evita que caches/CDN sirvam o header de
    // uma origem para outra.
    adicionarVary(res, 'Origin');

    const origemBruta = req.headers.origin;

    // Sem Origin: não é requisição cross-origin de navegador
    // (curl, server-to-server, same-origin GET). Segue o fluxo normal.
    if (origemBruta === undefined) return next();

    const origem = normalizarOrigem(origemBruta);
    const autorizada = origem ? await origemAutorizada(origem) : false;
    const preflight =
      req.method === 'OPTIONS' && req.headers['access-control-request-method'];

    if (!autorizada) {
      if (preflight || (rejeitar && !METODOS_SEGUROS.has(req.method))) {
        return res.status(403).json({
          erro: 'origem_nao_permitida',
          mensagem: 'A origem da requisição não está autorizada a consumir esta API.',
        });
      }
      // Leitura simples: segue sem headers CORS; o navegador bloqueia o acesso
      // da página à resposta.
      return next();
    }

    // Origem autorizada -> origem EXATA (nunca "*") + credenciais.
    res.setHeader('Access-Control-Allow-Origin', origem);
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (preflight) {
      const metodoSolicitado = String(
        req.headers['access-control-request-method']
      ).toUpperCase();

      if (
        !config.metodosPermitidos.includes(metodoSolicitado) ||
        !cabecalhosSolicitadosValidos(req.headers['access-control-request-headers'])
      ) {
        return res.status(403).json({
          erro: 'preflight_rejeitado',
          mensagem: 'Método ou cabeçalhos solicitados não são permitidos.',
        });
      }

      adicionarVary(res, 'Access-Control-Request-Method');
      adicionarVary(res, 'Access-Control-Request-Headers');
      res.setHeader('Access-Control-Allow-Methods', valorMetodos);
      res.setHeader(
        'Access-Control-Allow-Headers',
        config.cabecalhosPermitidos.join(', ')
      );
      res.setHeader('Access-Control-Max-Age', valorMaxAge);
      res.setHeader('Content-Length', '0');
      return res.status(204).end();
    }

    res.setHeader('Access-Control-Expose-Headers', valorExpostos);
    return next();
  };
}

module.exports = { criarMiddlewareCors, normalizarOrigem };

/* ------------------------------------------------------------------ *
 * Exemplo de uso (app.js)
 * ------------------------------------------------------------------ *
 *
 * const express = require('express');
 * const { criarMiddlewareCors } = require('./cors.middleware');
 * const db = require('./db'); // seu cliente (pg, knex, prisma...)
 *
 * const app = express();
 *
 * app.use(
 *   criarMiddlewareCors({
 *     origensFixas: [
 *       'https://app.suaplataforma.com',
 *       'https://admin.suaplataforma.com',
 *       'https://api.suaplataforma.com',
 *     ],
 *     origemCadastrada: async (origem) => {
 *       const { rowCount } = await db.query(
 *         `SELECT 1
 *            FROM tenant_allowed_origins o
 *            JOIN tenants t       ON t.id = o.tenant_id
 *            JOIN subscriptions s ON s.tenant_id = t.id
 *           WHERE o.origin = $1 AND o.verified = true
 *             AND t.status = 'active' AND s.status = 'active'
 *           LIMIT 1`,
 *         [origem]
 *       );
 *       return rowCount > 0;
 *     },
 *     aoErro: (e) => console.error('[cors] falha ao validar origem', e),
 *   })
 * );
 *
 * // Registre o CORS ANTES de sessão, autenticação, rate limit e rotas,
 * // para que preflights (que não levam cookies) nunca caiam em 401.
 *
 * ------------------------------------------------------------------ */