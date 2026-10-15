const express = require('express');
const app = express();

// Exemplo de dados; em produção, consulte o banco.
const clientes = [
  { id: 1, nome: 'Empresa Alpha' },
  { id: 2, nome: 'Empresa Beta' },
  { id: 3, nome: 'Alpha Tecnologia' }
];

app.get('/clientes', (req, res) => {
  const { nome } = req.query;

  const resultado = nome
    ? clientes.filter(cliente =>
        cliente.nome.toLowerCase().includes(nome.toLowerCase())
      )
    : clientes;

  res.json(resultado);
});

app.listen(3000);
