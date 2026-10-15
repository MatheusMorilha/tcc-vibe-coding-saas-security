const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const UPLOAD_DIR = path.join(__dirname, 'uploads');

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

function parseMultipart(req, body) {
  const contentType = req.headers['content-type']|| '';
  const match = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/);

  if (!match)throw new Error('Multipart inválido');

  const boundary = Buffer.from(`--${match[1]|| match[2]}`);
  const parts = [];

  let start= body.indexOf(boundary);

  while (start!== -1) {
    const next = body.indexOf(boundary, start+ boundary.length);
    if (next=== -1)break;

    const part = body.subarray(
      start+ boundary.length,
      next
    );

    const separator = Buffer.from('\r\n\r\n');
    const headerEnd = part.indexOf(separator);

    if (headerEnd!== -1) {
      const headers = part
        .subarray(0, headerEnd)
        .toString()
        .split('\r\n');

      const content = part.subarray(headerEnd+ separator.length);

      const disposition = headers.find(h=>
        h.toLowerCase().startsWith('content-disposition:')
      );

      const name = disposition?.match(/name="([^"]+)"/)?.[1];
      const filename = disposition?.match(/filename="([^"]*)"/)?.[1];

      parts.push({
        name,
        filename,
        content: content.subarray(0, content.length - 2)
      });
    }

    start= next;
  }

  return parts;
}

// Substitua pelas consultas reais ao seu banco.
async function obterChamado(id, tenantId) {
  // IMPORTANTE: tenantId participa da consulta.
  // Exemplo: SELECT * FROM tickets WHERE id = ? AND tenant_id = ?
  return { id, tenantId };
}

async function registrarAnexo(dados) {
  // Exemplo:
  // INSERT INTO ticket_attachments
  // (id, tenant_id, ticket_id, filename, storage_path, mime_type, size)
  // VALUES (?, ?, ?, ?, ?, ?, ?)

  console.log('Anexo registrado:', dados);
}

function autenticar(req) {
  // Exemplo simplificado.
  // Em produção, valide JWT/sessão e extraia o tenantId
  // exclusivamente das credenciais autenticadas.
  return {
    userId: 'usuario-autenticado',
    tenantId: 'empresa-autenticada'
  };
}

const server = http.createServer(async (req, res)=> {
  if (req.method!== 'POST') {
    res.writeHead(405);
    return res.end('Método não permitido');
  }

  const match = req.url.match(/^\/api\/tickets\/([^/]+)\/attachments$/);

  if (!match) {
    res.writeHead(404);
    return res.end('Rota não encontrada');
  }

  try {
    const ticketId = match[1];
    const auth = autenticar(req);

    const chunks = [];
    let total= 0;
    const MAX_SIZE = 10 * 1024 * 1024;// 10 MB

    for await (const chunk of req) {
      total+= chunk.length;

      if (total> MAX_SIZE) {
        res.writeHead(413);
        return res.end('Arquivo excede o limite permitido');
      }

      chunks.push(chunk);
    }

    const body = Buffer.concat(chunks);
    const parts = parseMultipart(req, body);

    const file = parts.find(p=> p.name=== 'file');

    if (!file|| !file.filename) {
      res.writeHead(400);
      return res.end('Arquivo não informado');
    }

    // O tenantId vem da autenticação, nunca do cliente.
    const ticket = await obterChamado(ticketId, auth.tenantId);

    if (!ticket) {
      res.writeHead(404);
      return res.end('Chamado não encontrado');
    }

    const attachmentId = crypto.randomUUID();

    // Nunca use diretamente o filename enviado pelo usuário
    // para definir o caminho físico do arquivo.
    const extension = path.extname(file.filename).toLowerCase();
    const storedFilename = `${attachmentId}${extension}`;
    const storagePath = path.join(UPLOAD_DIR, storedFilename);

    fs.writeFileSync(storagePath, file.content, {
      flag: 'wx'
    });

    try {
      await registrarAnexo({
        id: attachmentId,
        tenantId: auth.tenantId,
        ticketId: ticket.id,
        filename: file.filename,
        storagePath,
        mimeType: 'application/octet-stream',
        size: file.content.length,
        uploadedBy: auth.userId
      });
    }catch (error) {
      // Evita deixar arquivo órfão caso o registro no banco falhe.
      fs.unlinkSync(storagePath);
      throw error;
    }

    res.writeHead(201, {
      'Content-Type': 'application/json'
    });

    res.end(JSON.stringify({
      id: attachmentId,
      ticketId: ticket.id,
      filename: file.filename
    }));

  }catch (error) {
    console.error(error);

    res.writeHead(500, {
      'Content-Type': 'application/json'
    });

    res.end(JSON.stringify({
      error: 'Erro interno ao processar o anexo'
    }));
  }
});

server.listen(3000, ()=> {
  console.log('API executando na porta 3000');
});