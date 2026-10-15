const http = require('http');

const PORT = process.env.PORT || 3000;

async function checkDatabase() {
  // Substitua por uma consulta real ao seu driver de banco.
  return { status: 'ok' };
}

async function checkCache() {
  // Substitua por um PING real ao Redis/cache utilizado.
  return { status: 'ok' };
}

async function healthCheck() {
  const services = {};

  for (const [name, check]of Object.entries({
    database: checkDatabase,
    cache: checkCache
  })) {
    try {
      services[name]= await Promise.race([
        check(),
        new Promise((_, reject)=>
          setTimeout(()=> reject(new Error('timeout')), 2000)
        )
      ]);
    }catch (error) {
      services[name]= {
        status: 'error',
        error: error.message
      };
    }
  }

  const healthy = Object.values(services)
    .every(service=> service.status=== 'ok');

  return {
    status: healthy? 'ok' : 'degraded',
    services,
    timestamp: new Date().toISOString()
  };
}

const server = http.createServer(async (req, res)=> {
  if (req.method=== 'GET' && req.url=== '/health') {
    const result = await healthCheck();

    res.writeHead(result.status=== 'ok' ? 200 : 503, {
      'Content-Type': 'application/json'
    });

    return res.end(JSON.stringify(result));
  }

  res.writeHead(404, {'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT);