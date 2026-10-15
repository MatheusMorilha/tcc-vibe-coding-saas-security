const http = require("http");
const {URL }= require("url");
const {Pool }= require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const ALLOWED_SORT_COLUMNS = {
  name: "name",
  start_date: "start_date",
  end_date: "end_date",
  created_at: "created_at"
};

function getTenantId(req) {
  // Em produção, deve vir do contexto autenticado (JWT/session),
  // e não diretamente de um parâmetro fornecido pelo cliente.
  return req.user.tenantId;
}

async function listContracts(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);

  const sortParam = url.searchParams.get("sort")|| "created_at";
  const directionParam =
    (url.searchParams.get("direction")|| "desc").toLowerCase();

  const sortColumn = ALLOWED_SORT_COLUMNS[sortParam];

  if (!sortColumn) {
    res.writeHead(400, {"Content-Type": "application/json" });
    return res.end(JSON.stringify({
      error: "Invalid sort column"
    }));
  }

  if (!["asc", "desc"].includes(directionParam)) {
    res.writeHead(400, {"Content-Type": "application/json" });
    return res.end(JSON.stringify({
      error: "Invalid sort direction"
    }));
  }

  const tenantId = getTenantId(req);

  const sql = `
    SELECT id, name, start_date, end_date, created_at
    FROM contracts
    WHERE tenant_id = $1
    ORDER BY${sortColumn} ${directionParam.toUpperCase()}
  `;

  try {
    const {rows }= await pool.query(sql, [tenantId]);

    res.writeHead(200, {
      "Content-Type": "application/json"
    });

    res.end(JSON.stringify(rows));
  }catch (error) {
    console.error(error);

    res.writeHead(500, {
      "Content-Type": "application/json"
    });

    res.end(JSON.stringify({
      error: "Internal server error"
    }));
  }
}

const server = http.createServer(async (req, res)=> {
  if (req.method=== "GET" && req.url.startsWith("/contracts")) {
    return listContracts(req, res);
  }

  res.writeHead(404, {"Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(3000);