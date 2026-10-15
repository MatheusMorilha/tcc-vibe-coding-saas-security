const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {pipeline }= require('stream/promises');

const app = express();

app.use(express.json({ limit: '10kb' }));

const LOGO_DIR = path.join(__dirname, 'storage', 'logos');
const MAX_LOGO_SIZE = 2 * 1024 * 1024;// 2 MB

fs.mkdirSync(LOGO_DIR, { recursive: true });

/*
 * Middleware de autenticação ilustrativo.
 * Em produção, o tenantId deve vir das claims do token/sessão
 * após validação da identidade e autorização do usuário.
 */
function authenticate(req, res, next) {
  // Exemplo:
  // req.user = { id: "...", tenantId: "empresa-123" };

  if (!req.user|| !req.user.tenantId) {
    return res.status(401).json({ error: 'Não autenticado' });
  }

  next();
}

function isPrivateIPv4(hostname) {
  const parts = hostname.split('.').map(Number);

  if (
    parts.length !== 4 ||
    parts.some(Number.isNaN)||
    parts.some(part=> part< 0 || part> 255)
  ) {
    return false;
  }

  const [a, b]= parts;

  return (
    a=== 10 ||
    a=== 127 ||
    a=== 0 ||
    (a=== 172 && b>= 16 && b<= 31)||
    (a=== 192 && b=== 168)
  );
}

function validateUrl(value) {
  let url;

  try {
    url= new URL(value);
  }catch {
    throw new Error('URL inválida');
  }

  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Somente URLs HTTP e HTTPS são permitidas');
  }

  if (url.username|| url.password) {
    throw new Error('URLs com credenciais não são permitidas');
  }

  /*
   * Em produção, faça também resolução DNS e verifique o IP
   * de cada redirect para impedir SSRF contra a rede interna.
   */
  if (isPrivateIPv4(url.hostname)) {
    throw new Error('Destino não permitido');
  }

  return url;
}

app.post('/api/account/logo', authenticate, async (req, res)=> {
  const {url }= req.body;
  const tenantId = req.user.tenantId;

  if (typeof url!== 'string') {
    return res.status(400).json({
      error: 'O campo "url" é obrigatório'
    });
  }

  let imageUrl;

  try {
    imageUrl= validateUrl(url);
  }catch (error) {
    return res.status(400).json({
      error: error.message
    });
  }

  /*
   * O nome do arquivo é gerado pelo servidor.
   * Nunca usamos diretamente o tenantId ou o nome fornecido
   * pelo cliente como caminho no filesystem.
   */
  const fileName = `${crypto.randomUUID()}.img`;
  const filePath = path.join(LOGO_DIR, fileName);

  try {
    const response = await fetch(imageUrl, {
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000)
    });

    if (!response.ok) {
      return res.status(400).json({
        error: 'Não foi possível baixar a imagem'
      });
    }

    const contentType = response.headers.get('content-type')|| '';

    if (!contentType.startsWith('image/')) {
      return res.status(400).json({
        error: 'A URL não aponta para uma imagem'
      });
    }

    const contentLength = Number(
      response.headers.get('content-length')|| 0
    );

    if (contentLength> MAX_LOGO_SIZE) {
      return res.status(413).json({
        error: 'A imagem excede o tamanho máximo permitido'
      });
    }

    if (!response.body) {
      return res.status(400).json({
        error: 'Resposta sem conteúdo'
      });
    }

    /*
     * O limite é aplicado durante o streaming, e não apenas
     * através do Content-Length, pois esse header pode estar ausente
     * ou ser incorreto.
     */
    let received= 0;

    const limitedStream = response.body.pipeThrough(
      new TransformStream({
        transform(chunk, controller) {
          received+= chunk.byteLength;

          if (received> MAX_LOGO_SIZE) {
            controller.error(new Error('IMAGE_TOO_LARGE'));
            return;
          }

          controller.enqueue(chunk);
        }
      })
    );

    await pipeline(
      limitedStream,
      fs.createWriteStream(filePath, {
        flags: 'wx'
      })
    );

    /*
     * O registro no banco deve associar explicitamente o arquivo
     * ao tenant autenticado.
     *
     * Exemplo conceitual:
     *
     * await db.account.update({
     *   where: { tenantId },
     *   data: { logoPath: fileName }
     * });
     */

    return res.status(201).json({
      message: 'Logotipo armazenado com sucesso',
      logo: fileName
    });

  }catch (error) {
    await fs.promises.rm(filePath, { force: true }).catch(()=> {});

    if (error.message=== 'IMAGE_TOO_LARGE') {
      return res.status(413).json({
        error: 'A imagem excede o tamanho máximo permitido'
      });
    }

    console.error('Erro ao armazenar logotipo:', error);

    return res.status(502).json({
      error: 'Não foi possível obter ou armazenar a imagem'
    });
  }
});

app.listen(3000, ()=> {
  console.log('API ouvindo na porta 3000');
});