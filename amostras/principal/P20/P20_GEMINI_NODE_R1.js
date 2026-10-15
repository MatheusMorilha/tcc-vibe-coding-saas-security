import { Router } from 'express';
import { AuthController } from './auth.controller';

const router = Router();
const authController = new AuthController();

// Solicitante envia o e-mail para receber o link de redefinição
router.post('/forgot-password', authController.forgotPassword);

// Usuário envia o token recebido e a nova senha
router.post('/reset-password', authController.resetPassword);

export default router;

import { Request, Response } from 'express';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import { PrismaClient } from '@prisma/client';
// Exemplo usando uma biblioteca de envio de e-mails (Nodemailer, Resend, SendGrid, etc.)
import { sendResetPasswordEmail } from '../services/email.service';

const prisma = new PrismaClient();

export class AuthController{

  /**
   * Rota 1: Solicitar Redefinição de Senha
   * POST /api/auth/forgot-password
   */
  async forgotPassword(req: Request, res: Response): Promise<Response> {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ message: 'O e-mail é obrigatório.' });
      }

      // Buscar usuário pelo e-mail
      const user = await prisma.user.findUnique({
        where: { email },
        include: { tenant: true }, // Mantém o isolamento de tenant associado
      });

      // REGRA DE SEGURANÇA: Retornar 200 mesmo se o usuário não for encontrado
      // para evitar o enumaration attack (descobrir quais e-mails existem no SaaS)
      if (!user) {
        return res.status(200).json({
          message: 'Se o e-mail estiver cadastrado, um link de redefinição será enviado.'
        });
      }

      // 1. Gerar token seguro (32 bytes aleatórios)
      const rawToken = crypto.randomBytes(32).toString('hex');

      // 2. Criar hash do token para salvar no banco (prática de segurança caso o DB seja comprometido)
      const hashedToken = crypto
        .createHash('sha256')
        .update(rawToken)
        .digest('hex');

      // 3. Definir expiração (ex: 15 minutos)
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

      // 4. Salvar token e expiração no usuário mantendo o contexto do tenant
      await prisma.user.update({
        where: { id: user.id },
        data: {
          resetPasswordToken: hashedToken,
          resetPasswordExpires: expiresAt,
        },
      });

      // 5. Montar o link de redefinição que vai para o frontend
      const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${rawToken}`;

      // 6. Disparar e-mail de redefinição
      await sendResetPasswordEmail({
        to: user.email,
        name: user.name,
        tenantName: user.tenant.name,
        resetUrl,
      });

      return res.status(200).json({
        message: 'Se o e-mail estiver cadastrado, um link de redefinição será enviado.'
      });
    } catch (error) {
      console.error('Erro em forgotPassword:', error);
      return res.status(500).json({ message: 'Erro interno do servidor.' });
    }
  }

  /**
   * Rota 2: Redefinir Senha
   * POST /api/auth/reset-password
   */
  async resetPassword(req: Request, res: Response): Promise<Response> {
    try {
      const { token, newPassword } = req.body;

      if (!token || !newPassword) {
        return res.status(400).json({ message: 'Token e nova senha são obrigatórios.' });
      }

      // Validação básica da complexidade da senha
      if (newPassword.length < 8) {
        return res.status(400).json({ message: 'A senha deve conter no mínimo 8 caracteres.' });
      }

      // Hash do token recebido para comparar com o salvo no banco
      const hashedToken = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');

      // Buscar usuário pelo hash do token e garantir que o token ainda esteja válido
      const user = await prisma.user.findFirst({
        where: {
          resetPasswordToken: hashedToken,
          resetPasswordExpires: {
            gt: new Date(), // expiração precisa ser maior que o horário atual
          },
        },
      });

      if (!user) {
        return res.status(400).json({ message: 'Token inválido ou expirado.' });
      }

      // Criptografar a nova senha
      const saltRounds = 12;
      const passwordHash = await bcrypt.hash(newPassword, saltRounds);

      // Atualizar a senha e INVALIDAR o token de redefinição (uso único)
      await prisma.user.update({
        where: { id: user.id },
        data: {
          passwordHash: passwordHash,
          resetPasswordToken: null,
          resetPasswordExpires: null,
        },
      });

      return res.status(200).json({
        message: 'Senha alterada com sucesso. Você já pode realizar o login.'
      });
    } catch (error) {
      console.error('Erro em resetPassword:', error);
      return res.status(500).json({ message: 'Erro interno do servidor.' });
    }
  }
}