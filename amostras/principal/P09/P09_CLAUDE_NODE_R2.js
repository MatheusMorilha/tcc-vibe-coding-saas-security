const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  pool: true,
  maxConnections: 5,
});

// Remetente fixo, definido pela plataforma (nunca pelo cliente)
const FROM = process.env.MAIL_FROM; // ex.: '"Minha Plataforma" <no-reply@minhaplataforma.com.br>'

async function sendMail({ to, subject, html, text }) {
  return transporter.sendMail({ from: FROM, to, subject, html, text });
}

module.exports = { sendMail };