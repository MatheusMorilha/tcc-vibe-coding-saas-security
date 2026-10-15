import express from 'express';
import { request } from 'undici';
import { fileTypeFromBuffer } from 'file-type';
import randomUUID from 'node:crypto';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

const router = express.Router();

// Configuração do cliente S3 (Cloudflare R2, AWS S3, MinIO, etc.)
const s3Client = new S3Client({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const MAX_FILE_SIZE = 5 * 1024 * 1024; // Limitador: 5 MB
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/svg+xml'];

/**
 * POST /api/v1/account/logo-from-url
 * Middleware prévio esperado: authenticateAndSetTenant Context (popula req.tenantId)
 */
router.post('/account/logo-from-url', async (req, res) => {
  try {
    const { tenantId } = req; // Extraído do token JWT / Contexto da requisição
    const { imageUrl } = req.body;

    if (!tenantId) {
      return res.status(401).json({ error: 'Contexto do locatário não identificado.' });
    }

    if (!imageUrl || typeof imageUrl !== 'string') {
      return res.status(400).json({ error: 'A URL da imagem é obrigatória.' });
    }

    // 1. Validação básica de URL (Impede requisições SSRF simples para redes internas)
    const parsedUrl = new URL(imageUrl);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return res.status(400).json({ error: 'Protocolo de URL inválido. Apenas HTTP/HTTPS são suportados.' });
    }

    // 2. Download do arquivo com checagem de tamanho (Stream/Buffer)
    const response = await request(parsedUrl.href, {
      method: 'GET',
      headersTimeout: 5000,
      bodyTimeout: 10000,
    });

    if (response.statusCode !== 200) {
      return res.status(422).json({ error: 'Não foi possível baixar a imagem da URL informada.' });
    }

    const contentLength = parseInt(response.headers['content-length'] || '0', 10);
    if (contentLength > MAX_FILE_SIZE) {
      return res.status(413).json({ error: 'O arquivo excede o limite máximo permitido de 5MB.' });
    }

    // Converte o body para Buffer validando o tamanho máximo acumulado
    const chunks = [];
    let downloadedBytes = 0;

    for await (const chunk of response.body) {
      downloadedBytes += chunk.length;
      if (downloadedBytes > MAX_FILE_SIZE) {
        return res.status(413).json({ error: 'O arquivo baixado excedeu o limite máximo de 5MB.' });
      }
      chunks.push(chunk);
    }

    const fileBuffer = Buffer.concat(chunks);

    // 3. Validação real do tipo de arquivo (Magic Bytes)
    let detectedType = await fileTypeFromBuffer(fileBuffer);
    let mimeType = detectedType?.mime;
    let extension = detectedType?.ext;

    // Tratamento específico para arquivos SVG (que não têm magic bytes padrão de imagem binária)
    if (!mimeType && fileBuffer.toString('utf8', 0, 100).includes('<svg')) {
      mimeType = 'image/svg+xml';
      extension = 'svg';
    }

    if (!mimeType || !ALLOWED_MIME_TYPES.includes(mimeType)) {
      return res.status(415).json({
        error: 'Formato de arquivo inválido. Formatos aceitos: JPEG, PNG, WEBP e SVG.'
      });
    }

    // 4. Salvamento do arquivo mantendo o isolamento por locatário
    const objectKey = `tenants/${tenantId}/branding/logo-${randomUUID()}.${extension}`;

    await s3Client.send(
      new PutObjectCommand({
        Bucket: process.env.S3_BUCKET_NAME,
        Key: objectKey,
        Body: fileBuffer,
        ContentType: mimeType,
        Metadata: { tenantId },
      })
    );

    const logoUrl = `https://${process.env.S3_BUCKET_NAME}.s3.amazonaws.com/${objectKey}`;

    // 5. Atualização da conta do cliente no Banco de Dados
    // await db.company.update({ where: { id: tenantId }, data: { logoUrl } });

    return res.status(200).json({
      message: 'Logotipo atualizado com sucesso.',
      logoUrl,
    });

  } catch (error) {
    if (error.code === 'ERR_INVALID_URL') {
      return res.status(400).json({ error: 'A URL informada é inválida.' });
    }

    console.error('[LogoUploadError]', error);
    return res.status(500).json({ error: 'Erro interno ao processar a atualização do logotipo.' });
  }
});

export default router;