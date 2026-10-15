// routes/relatorios.js
const express = require('express');
const router = express.Router();
const { z } = require('zod');
const db = require('../db'); // pool de conexão (pg)
const { autenticar } = require('../middlewares/auth');

// Validação estrita dos parâmetros de entrada
const querySchema = z.object({
  empresaId: z.string().uuid(),
  dataInicio: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  dataFim: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
});

router.get('/empresas/:empresaId/relatorios/financeiro', autenticar, async (req, res) => {
  try {
    // 1. Validar entrada
    const parsed = querySchema.safeParse({
      empresaId: req.params.empresaId,
      dataInicio: req.query.dataInicio,
      dataFim: req.query.dataFim,
    });

    if (!parsed.success) {
      return res.status(400).json({
        erro: 'Parâmetros inválidos',
        detalhes: parsed.error.flatten(),
      });
    }

    const { empresaId, dataInicio, dataFim } = parsed.data;

    if (new Date(dataInicio) > new Date(dataFim)) {
      return res.status(400).json({ erro: 'dataInicio não pode ser posterior a dataFim' });
    }

    // 2. ISOLAMENTO DE TENANT — ponto crítico.
    // Nunca confiar apenas no parâmetro da URL: o usuário autenticado
    // (req.usuario, populado pelo middleware `autenticar`) precisa
    // pertencer à empresa solicitada.
    if (req.usuario.empresaId !== empresaId) {
      // Log de tentativa de acesso indevido (auditoria de segurança)
      console.warn(
        `Tentativa de acesso cross-tenant: usuário ${req.usuario.id} ` +
        `(empresa ${req.usuario.empresaId}) tentou acessar empresa ${empresaId}`
      );
      return res.status(403).json({ erro: 'Acesso não autorizado a este recurso' });
    }

    // 3. Verificar se a empresa possui assinatura ativa
    const { rows: empresaRows } = await db.query(
      `SELECT id, plano_id, status_assinatura
       FROM empresas
       WHERE id = $1`,
      [empresaId]
    );

    if (empresaRows.length === 0) {
      return res.status(404).json({ erro: 'Empresa não encontrada' });
    }

    if (empresaRows[0].status_assinatura !== 'ativa') {
      return res.status(402).json({ erro: 'Assinatura inativa. Renove seu plano para gerar relatórios.' });
    }

    // 4. Query consolidada — sempre filtrando por empresa_id (parametrizado)
    const { rows: lancamentos } = await db.query(
      `SELECT tipo, categoria, SUM(valor) AS total
       FROM lancamentos_financeiros
       WHERE empresa_id = $1
         AND data_lancamento BETWEEN $2 AND $3
       GROUP BY tipo, categoria
       ORDER BY tipo, categoria`,
      [empresaId, dataInicio, dataFim]
    );

    // 5. Consolidação em memória
    const receitas = lancamentos.filter(l => l.tipo === 'receita');
    const despesas = lancamentos.filter(l => l.tipo === 'despesa');

    const totalReceitas = receitas.reduce((acc, l) => acc + Number(l.total), 0);
    const totalDespesas = despesas.reduce((acc, l) => acc + Number(l.total), 0);

    const relatorio = {
      empresaId,
      periodo: { inicio: dataInicio, fim: dataFim },
      totalReceitas,
      totalDespesas,
      saldoLiquido: totalReceitas - totalDespesas,
      detalhamento: {
        receitas: receitas.map(r => ({ categoria: r.categoria, total: Number(r.total) })),
        despesas: despesas.map(d => ({ categoria: d.categoria, total: Number(d.total) })),
      },
      geradoEm: new Date().toISOString(),
    };

    return res.status(200).json(relatorio);
  } catch (erro) {
    console.error('Erro ao gerar relatório financeiro:', erro);
    return res.status(500).json({ erro: 'Erro interno ao gerar relatório' });
  }
});

module.exports = router;