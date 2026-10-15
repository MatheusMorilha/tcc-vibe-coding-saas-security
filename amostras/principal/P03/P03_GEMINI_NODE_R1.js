const express = require('express');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { pipeline } = require('stream/promises');

const router = express.Router();

// Configurações de limite e segurança
const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/svg+xml'];

/**
 * POST /api/v1/account/logo
 * Baixa uma imagem via URL informada e atualiza o logotipo do tenant.
 */
router.post('/api/v1/account/logo', async (req, res) => {
  const { imageUrl } = req.body;
  // Assumindo que o tenantId é injetado pelo middleware de autenticação/contexto
  const tenantId = req.tenantId || req.headers['x-tenant-id'];

  if (!tenantId) {
    return res.status(401).json({ error: 'Contexto do cliente (Tenant) não identificado.' });
  }

  if (!imageUrl) {
    return res.status(400).json({ error: 'A URL da imagem é obrigatória.' });
  }

  // Validação básica do formato da URL
  try {
    new URL(imageUrl);
  } catch (_) {
    return res.status(400).json({ error: 'URL informada é inválida.' });
  }

  try {
    // 1. Requisição HEAD para validar Content-Type e Content-Length antes de baixar
    const headResponse = await axios.head(imageUrl, { timeout: 5000 });
    const contentType = headResponse.headers['content-type'];
    const contentLength = parseInt(headResponse.headers['content-length'] || '0', 10);

    if (contentType && !ALLOWED_MIME_TYPES.includes(contentType)) {
      return res.status(422).json({
        error: `Formato de imagem não suportado. Permitidos: ${ALLOWED_MIME_TYPES.join(', ')}`,
      });
    }

    if (contentLength > MAX_FILE_SIZE_BYTES) {
      return res.status(413).json({ error: 'O arquivo excede o limite máximo de 5MB.' });
    }

    // 2. Download do arquivo via Stream
    const response = await axios({
      method: 'get',
      url: imageUrl,
      responseType: 'stream',
      timeout: 10000,
      maxContentLength: MAX_FILE_SIZE_BYTES,
    });

    const finalContentType = response.headers['content-type'] || contentType;
    if (!ALLOWED_MIME_TYPES.includes(finalContentType)) {
      return res.status(422).json({ error: 'Conteúdo baixado não é uma imagem válida.' });
    }

    // Mapping da extensão com base no MIME type
    const extensionMap = {
      'image/jpeg': '.jpg',
      'image/png': '.png',
      'image/webp': '.webp',
      'image/svg+xml': '.svg',
    };
    const ext = extensionMap[finalContentType] || '.img';

    // 3. Estruturação do caminho do arquivo isolado por Tenant
    const uploadDir = path.join(__dirname, '..', 'uploads', 'tenants', String(tenantId));
    await fs.promises.mkdir(uploadDir, { recursive: true });

    const filename = `logo_${Date.now()}${ext}`;
    const filePath = path.join(uploadDir, filename);

    // 4. Salva o arquivo no disco via pipeline stream
    const writer = fs.createWriteStream(filePath);
    await pipeline(response.data, writer);

    const logoUrl = `/uploads/tenants/${tenantId}/${filename}`;

    // 5. Atualiza o registro da empresa no banco de dados
    // Exemplo com query genérica/ORM:
    // await TenantModel.update({ logoUrl }, { where: { id: tenantId } });

    return res.status(200).json({
      message: 'Logotipo atualizado com sucesso.',
      data: {
        tenantId,
        logoUrl,
      },
    });
  } catch (error) {
    console.error(`[Logo Upload Error] Tenant: ${tenantId}`, error.message);

    if (error.code === 'ECONNABORTED') {
      return res.status(504).json({ error: 'Tempo limite esgotado ao tentar baixar a imagem.' });
    }

    return res.status(500).json({ error: 'Falha ao processar e salvar a imagem do logotipo.' });
  }
});

module.exports = router;