'use strict';

const crypto = require('node:crypto');

const ALGORITMO = 'aes-256-gcm';
const VERSAO_CHAVE = process.env.ERP_CRED_KEY_VERSION || 'v1';

function obterChave() {
  // Chave de 32 bytes em base64. Em produção, obtenha via KMS / Secrets Manager.
  const chave = Buffer.from(process.env.ERP_CRED_KEY || '', 'base64');
  if (chave.length !== 32) {
    throw new Error('ERP_CRED_KEY inválida: esperado 32 bytes em base64');
  }
  return chave;
}

/**
 * Criptografa um objeto JSON. O empresaId entra como AAD (dado autenticado
 * adicional): um registro copiado para outra empresa não será decifrado.
 */
function criptografar(objeto, empresaId) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITMO, obterChave(), iv);
  cipher.setAAD(Buffer.from(String(empresaId)));

  const cifrado = Buffer.concat([
    cipher.update(JSON.stringify(objeto), 'utf8'),
    cipher.final(),
  ]);

  return {
    payload: cifrado.toString('base64'),
    iv: iv.toString('base64'),
    authTag: cipher.getAuthTag().toString('base64'),
    keyVersion: VERSAO_CHAVE,
  };
}

function descriptografar({ payload, iv, authTag }, empresaId) {
  const decipher = crypto.createDecipheriv(
    ALGORITMO,
    obterChave(),
    Buffer.from(iv, 'base64'),
  );
  decipher.setAAD(Buffer.from(String(empresaId)));
  decipher.setAuthTag(Buffer.from(authTag, 'base64'));

  const claro = Buffer.concat([
    decipher.update(Buffer.from(payload, 'base64')),
    decipher.final(),
  ]);
  return JSON.parse(claro.toString('utf8'));
}

module.exports = { criptografar, descriptografar };