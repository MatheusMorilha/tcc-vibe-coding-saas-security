const http = require('http');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Chave secreta para assinatura do JWT (deve ser armazenada em variável de ambiente)
const JWT_SECRET = process.env.JWT_SECRET || 'sua_chave_secreta_super_segura';
const JWT_EXPIRES_IN = '8h';

/**
 * Simulação de busca na base de dados relacional compartilhada.
 * Substitua pelo seu ORM/Query Builder (ex: Prisma, TypeORM, Knex, pg).
 */
async function findUserByEmail(email){
  // Query conceitual no banco multilocatário:
  // SELECT u.id, u.email, u.password_hash, u.tenant_id, t.status AS tenant_status, t.plan
  // FROM users u
  // JOIN tenants t ON u.tenant_id = t.id
  // WHERE u.email = $1;

  if (email === 'usuario@empresa.com') {
    return {
      id: 'usr_12345',
      email: 'usuario@empresa.com',
      // Senha hash simulada para "SenhaSegura123"
      passwordHash: '$2a$12$KIXpZ2hP0mJ3sN7k.8Q2UeX9V8l7.bC0E3fQ21yP8Y.n.S6.aZ1yC',
      tenantId: 'tenant_abc99',
      tenantStatus: 'active', // Estado da assinatura da empresa
      role: 'admin'
    };
  }
  return null;
}

/**
 * Handler da rota POST /api/v1/auth/login
 */
async function handleLogin(req, res){
  let body = '';

  // Captura dos dados da requisição
  req.on('data', chunk => {
    body += chunk.toString();
  });

  req.on('end', async () => {
    try {
      // 1. Parsing do payload
      if (!body) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'O corpo da requisição não pode estar vazio.' }));
      }

      const { email, password } = JSON.parse(body);

      // 2. Validação dos campos obrigatórios
      if (!email || !password) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'E-mail e senha são obrigatórios.' }));
      }

      // 3. Busca do usuário na base de dados
      const user = await findUserByEmail(email.toLowerCase().trim());
      if (!user) {
        // Mensagem genérica por segurança (evita enumeração de usuários)
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Credenciais inválidas.' }));
      }

      // 4. Validação da conta da empresa/tenant (Assinatura e Status)
      if (user.tenantStatus !== 'active') {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Acesso bloqueado: conta da empresa inativa ou pendente.' }));
      }

      // 5. Comparação da senha enviada com o hash armazenado
      const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
      if (!isPasswordValid) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Credenciais inválidas.' }));
      }

      // 6. Geração do Payload do Token de Sessão (com contexto Multi-tenant)
      const tokenPayload = {
        sub: user.id,          // Subject: ID do Usuário
        tenant_id: user.tenantId, // Contexto da Empresa (Essencial para isolamento de dados)
        email: user.email,
        role: user.role
      };

      // 7. Assinatura do JWT
      const token = jwt.sign(tokenPayload, JWT_SECRET, {
        expiresIn: JWT_EXPIRES_IN
      });

      // 8. Resposta de sucesso
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        message: 'Autenticação realizada com sucesso.',
        token,
        user: {
          id: user.id,
          email: user.email,
          tenantId: user.tenantId,
          role: user.role
        }
      }));

    } catch (error) {
      console.error('[AUTH_ERROR]', error);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Erro interno no servidor ao realizar login.' }));
    }
  });
}

// Inicialização do servidor de teste
const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/api/v1/auth/login') {
    return handleLogin(req, res);
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Rota não encontrada.' }));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Servidor de Autenticação SaaS rodando na porta ${PORT}`);
});