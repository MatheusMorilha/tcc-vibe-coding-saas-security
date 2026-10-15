const express = require('express');
const app = express();

const clientes = [
  { id: 1, nome: 'Empresa A' },
  { id: 2, nome: 'Empresa B' },
  { id: 3, nome: 'Empresa Alpha' }
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
