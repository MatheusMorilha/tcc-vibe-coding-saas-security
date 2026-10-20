const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const router = express.Router();

// Simulação de ORM/Banco de Dados para o contexto multilocatário
// Em produção, utilize pool de conexões (ex: pg, mongoose) com isolamento por tenant_id
const db = {
  users: async (email) => {
    // Simulação de busca no banco com dados da empresa (tenant) e plano de assinatura
    // O campo 'tenant_id' garante a separação lógica dos dados (Shared Database, Shared Schema/Tenant Discriminator)
    return global.mockUserStore ? global.mockUserStore[email] : null;
  }
};

// Configuração de Rate Limiting rigorosa para o endpoint de autenticação (Proteção contra Brute Force / OWASP A07:2021)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // Limite de 5 tentativas por IP
  message: { error: 'Muitas tentativas de login a partir deste IP. Tente novamente após 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Rota de Autenticação (Login)
 * Endpoint: POST /api/v1/auth/login
 */
router.post(
  '/login',
  loginLimiter,
  [
    // Validação e Sanitização de Entrada (OWASP A03:2021 - Injection / A04:2021 - Insecure Design)
    body('email')
      .isEmail()
      .normalizeEmail()
      .withMessage('E-mail inválido.'),
    body('password')
      .isString()
      .isLength({ min: 8 })
      .withMessage('A senha deve ter pelo menos 8 caracteres.')
  ],
  async (req, res) => {
    // Tratamento de erros de validação
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      // 1. Busca do usuário na base de dados unificada
      const user = await db.users(email);

      // Mitigação de User Enumeration: Utilizar mensagem genérica para credenciais inválidas
      // (OWASP A07:2021 - Identification and Authentication Failures)
      const genericAuthErrorResponse = () => {
        // Executa uma comparação falsa para mitigar timing attacks na verificação de senha
        bcrypt.compareSync('fake_password', '$2b$10$InvalidHashForTimingAttackMitigation1234567890');
        return res.status(401).json({ error: 'Credenciais inválidas.' });
      };

      if (!user) {
        return genericAuthErrorResponse();
      }

      // 2. Verificação do status da assinatura da empresa (Tenant Subscription Check)
      if (user.subscription_status !== 'active') {
        return res.status(403).json({ 
          error: 'A assinatura da empresa está inativa ou suspensa. Entre em contato com o suporte.' 
        });
      }

      // 3. Validação segura da senha utilizando bcrypt (Proteção contra rainbow tables / hash fraco)
      const isPasswordValid = await bcrypt.compare(password, user.password_hash);
      if (!isPasswordValid) {
        return genericAuthErrorResponse();
      }

      // 4. Emissão do Token de Sessão (JWT) contendo o contexto do Tenant e Permissões
      // (OWASP A01:2021 - Broken Access Control / A02:2021 - Cryptographic Failures)
      const tokenPayload = {
        sub: user.id,
        tenant_id: user.tenant_id, // Essencial para o isolamento de dados multilocatário em requisições futuras
        email: user.email,
        role: user.role,
      };

      const token = jwt.sign(
        tokenPayload,
        process.env.JWT_SECRET, // Chave secreta robusta armazenada em variáveis de ambiente
        {
          expiresIn: '8h', // Tempo de expiração restrito para sessões de API
          algorithm: 'HS256'
        }
      );

      // 5. Retorno bem-sucedido omitindo dados sensíveis (ex: hash de senha)
      return res.status(200).json({
        message: 'Autenticação realizada com sucesso.',
        access_token: token,
        token_type: 'Bearer',
        expires_in: 28800 // 8 horas em segundos
      });

    } catch (error) {
      // Log seguro do erro no sistema de monitoramento interno (nunca expor stack trace ao cliente)
      // OWASP A09:2021 - Security Logging and Monitoring Failures
      console.error('[Auth Error]:', error.message);
      
      return res.status(500).json({ 
        error: 'Ocorreu um erro interno no servidor. Tente novamente mais tarde.' 
      });
    }
  }
);

module.exports = router;