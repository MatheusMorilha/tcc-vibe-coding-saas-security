const express = require('express');
const axios = require('axios');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { fileTypeFromStream } = require('file-type');
const path = require('path');

const router = express.Router();

// Configuração do cliente S3 (SaaS Multi-tenant)
const s3Client = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // Limitador: 5 MB
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/svg+xml'];

/**
 * POST /api/v1/account/logo/import-url
 * Middleware prévio esperado: authMiddleware (injeta req.tenantId e req.userId)
 */
router.post('/api/v1/account/logo/import-url', async (req, res) => {
  const { tenantId } = req; // Garantia de escopo do locatário (autenticado)
  const { imageUrl } = req.body;

  if (!tenantId) {
    return res.status(401).json({ error: 'Contexto de locatário não identificado.' });
  }

  // 1. Validação simples de entrada
  if (!imageUrl || typeof imageUrl !== 'string') {
    return res.status(400).json({ error: 'A URL da imagem é obrigatória.' });
  }

  try {
    const parsedUrl = new URL(imageUrl);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return res.status(400).json({ error: 'Apenas protocolos HTTP e HTTPS são permitidos.' });
    }
  } catch (err) {
    return res.status(400).json({ error: 'URL informada é inválida.' });
  }

  try {
    // 2. Realiza o download com stream para inspecionar tamanho e tipo sem carregar tudo na memória
    const response = await axios({
      method: 'get',
      url: imageUrl,
      responseType: 'stream',
      timeout: 10000, // Timeout de 10s para evitar conexões presas
      maxContentLength: MAX_FILE_SIZE_BYTES,
      headers: {
        'User-Agent': 'SaaS-LogoFetcher/1.0',
      },
    });

    // Validação preliminar do header Content-Length (se presente)
    const contentLength = parseInt(response.headers['content-length'], 10);
    if (contentLength && contentLength > MAX_FILE_SIZE_BYTES) {
      response.data.destroy();
      return res.status(400).json({ error: 'O arquivo excede o limite máximo de 5MB.' });
    }

    // 3. Inspeção do tipo de arquivo via buffer inicial (Magic Bytes)
    const stream = response.data;
    const detectedType = await fileTypeFromStream(stream);

    // Tratamento para SVG (que nem sempre é detectado por magic bytes como imagem convencional)
    const headerContentType = response.headers['content-type']?.split(';')[0].toLowerCase();
    const isSvg = headerContentType === 'image/svg+xml';

    const mimeType = detectedType ? detectedType.mime : (isSvg ? 'image/svg+xml' : null);

    if (!mimeType || !ALLOWED_MIME_TYPES.includes(mimeType)) {
      stream.destroy();
      return res.status(400).json({
        error: `Formato de imagem inválido. Formatos permitidos: PNG, JPEG, WEBP, SVG. (Detectado: ${mimeType || 'desconhecido'})`,
      });
    }

    // 4. Acúmulo do stream em memória com trava de tamanho em tempo de download
    const chunks = [];
    let downloadedBytes = 0;

    for await (const chunk of stream) {
      downloadedBytes += chunk.length;
      if (downloadedBytes > MAX_FILE_SIZE_BYTES) {
        stream.destroy();
        return res.status(400).json({ error: 'O arquivo excede o limite máximo de 5MB.' });
      }
      chunks.push(chunk);
    }

    const fileBuffer = Buffer.concat(chunks);

    // 5. Definição do caminho no S3 com isolamento lógico por Tenant
    const extension = detectedType ? detectedType.ext : (isSvg ? 'svg' : 'png');
    const s3Key = `tenants/${tenantId}/branding/logo.${extension}`;

    // 6. Upload para o S3
    const uploadParams = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: s3Key,
      Body: fileBuffer,
      ContentType: mimeType,
      CacheControl: 'max-age=31536000', // Cache no CDN/browser
      Metadata: {
        tenantId: String(tenantId),
        updatedBy: String(req.userId || 'system'),
      },
    };

    await s3Client.send(new PutObjectCommand(uploadParams));

    // Monte a URL final de acesso (CDN ou diretamente S3)
    const logoUrl = `https://${process.env.S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${s3Key}`;

    // 7. Atualização do banco de dados (Exemplo genérico via ORM/SQL)
    /*
      await db.tenant.update({
        where: { id: tenantId },
        data: { logoUrl: logoUrl, updatedAt: new Date() }
      });
    */

    return res.status(200).json({
      message: 'Logotipo atualizado com sucesso.',
      logoUrl: logoUrl,
      sizeBytes: downloadedBytes,
      mimeType: mimeType,
    });

  } catch (error) {
    console.error(`[LogoImportError] Tenant ${tenantId}:`, error.message);

    if (error.code === 'ECONNABORTED') {
      return res.status(504).json({ error: 'Tempo limite excedido ao baixar a imagem da URL fornecida.' });
    }

    return res.status(500).json({ error: 'Falha ao processar o download ou armazenamento do logotipo.' });
  }
});

module.exports = router;