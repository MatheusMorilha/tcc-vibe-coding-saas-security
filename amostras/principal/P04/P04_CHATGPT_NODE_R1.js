const cors = require('cors');

const allowedOrigins = new Set([
  'https://app.cliente-a.com',
  'https://app.cliente-b.com',
  'https://portal.cliente-c.com'
]);

const corsOptions = {
  origin(origin, callback) {
    // Permite requisições sem Origin (ex.: chamadas servidor-servidor).
    if (!origin) {
      return callback(null, true);
    }

    if (allowedOrigins.has(origin)) {
      return callback(null, true);
    }

    return callback(new Error('Origem não permitida pelo CORS'));
  },

  credentials: true,

  methods: [
    'GET',
    'POST',
    'PUT',
    'PATCH',
    'DELETE',
    'OPTIONS'
  ],

  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With'
  ],

  exposedHeaders: [
    'Content-Length',
    'Content-Range'
  ],

  maxAge: 600
};

module.exports = cors(corsOptions);