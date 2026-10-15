import { FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'node:crypto';
import { db } from './db'; // Seu ORM ou Query Builder (Prisma, Knex, Drizzle, etc.)

interface CreateApiKeyBody {
  name: string;
  expiresInDays?: number;
}

// Interface estendida com os dados do Tenant extraídos do Middleware de Autenticação
interface AuthenticatedRequest extends FastifyRequest {
  user: {
    id: string;
    companyId: string; // ID da empresa locatária (Tenant)
    role: string;
  };
}

/**
 * Utilitário para gerar uma API Key segura e o seu Hash
 */
function generateApiKey(environment: 'live' | 'test' = 'live'){
  const prefix = `sk_${environment}_`;
  const randomBytes = crypto.randomBytes(32).toString('hex');
  const rawKey = `${prefix}${randomBytes}`;

  // Hash SHA-256 da chave para armazenamento seguro
  const keyHash = crypto
    .createHash('sha256')
    .update(rawKey)
    .digest('hex');

  // Guardamos o prefixo e os primeiros caracteres para listagem no painel (ex: "sk_live_a1b2...8f")
  const keyPrefix = `${rawKey.substring(0, 12)}...${rawKey.slice(-4)}`;

  return { rawKey, keyHash, keyPrefix };
}

/**
 * Controller/Handler da Rota POST /api/v1/integration-keys
 */
export async function createApiKeyHandler(
  request: FastifyRequest<{ Body: CreateApiKeyBody }>,
  reply: FastifyReply){
  try {
    const { companyId } = (request as AuthenticatedRequest).user;
    const { name, expiresInDays } = request.body;

    // 1. Validação básica de entrada
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return reply.status(400).send({
        error: 'Bad Request',
        message: 'O nome da chave de integração é obrigatório.',
      });
    }

    // 2. Cálculo da data de expiração (se informada)
    let expiresAt: Date | null = null;
    if (expiresInDays && expiresInDays > 0) {
      expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + expiresInDays);
    }

    // 3. Geração da chave e hash
    const { rawKey, keyHash, keyPrefix } = generateApiKey('live');

    // 4. Persistência isolada por multilocação (company_id)
    const newApiKey = await db.apiKey.create({
      data: {
        companyId, // Garante que a chave pertença estritamente ao locatário solicitante
        name: name.trim(),
        keyHash,
        keyPrefix,
        expiresAt,
      },
      select: {
        id: true,
        name: true,
        keyPrefix: true,
        createdAt: true,
        expiresAt: true,
      },
    });

    // 5. Retorna a chave gerada apenas uma vez ao solicitante
    return reply.status(201).send({
      message: 'Chave de integração gerada com sucesso. Guarde-a em um local seguro.',
      apiKey: {
        id: newApiKey.id,
        name: newApiKey.name,
        secretKey: rawKey, // ATENÇÃO: Texto plano retornado SOMENTE nesta resposta
        keyPrefix: newApiKey.keyPrefix,
        createdAt: newApiKey.createdAt,
        expiresAt: newApiKey.expiresAt,
      },
    });
  } catch (error) {
    request.log.error(error);
    return reply.status(500).send({
      error: 'Internal Server Error',
      message: 'Erro ao gerar a chave de integração.',
    });
  }
}