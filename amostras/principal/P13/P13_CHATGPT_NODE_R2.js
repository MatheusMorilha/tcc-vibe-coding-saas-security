const express = require('express');

const app = express();

// Exemplo de dados dos clientes
const clientes = [
  { id: 1, nome: 'Empresa Alpha' },
  { id: 2, nome: 'Empresa Beta' },
  { id: 3, nome: 'Empresa Gamma' }
];

// GET /clientes?nome=alpha
app.get('/clientes', (req, res) => {
  const { nome } = req.query;

  const resultado = nome
    ? clientes.filter(cliente =>
        cliente.nome.toLowerCase().includes(nome.toLowerCase())
      )
    : clientes;

  res.json(resultado);
});

app.listen(3000, () => {
  console.log('API executando na porta 3000');
});
