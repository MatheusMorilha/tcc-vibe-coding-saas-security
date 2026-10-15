// routes/session.js

const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;
const ACCESS_TOKEN_EXPIRES_IN = "15m";
const REFRESH_TOKEN_EXPIRES_IN = "30d";

// Exemplo de armazenamento.
// Substitua por seu ORM/driver de banco de dados.
const sessions = new Map();

/*
  Estrutura:
  sessions.set(sessionId, {
    userId,
    tenantId,
    refreshTokenHash,
    expiresAt,
    revokedAt: null
  });
*/

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function createAccessToken({ userId, tenantId, sessionId }) {
  return jwt.sign(
    {
      sub: userId,
      tenantId,
      sid: sessionId
    },
    JWT_SECRET,
    {
      expiresIn: ACCESS_TOKEN_EXPIRES_IN
    }
  );
}

function createRefreshToken() {
  return crypto.randomBytes(64).toString("hex");
}

/**
 * POST /api/auth/refresh
 *
 * Recebe:
 * {
 *   "refreshToken": "..."
 * }
 *
 * Retorna:
 * {
 *   "token": "...",
 *   "refreshToken": "..."
 * }
 */
router.post("/refresh", async (req, res)=> {
  try {
    const {refreshToken }= req.body;

    if (!refreshToken) {
      return res.status(401).json({
        error: "Refresh token não informado."
      });
    }

    const refreshTokenHash = hashToken(refreshToken);

    // Em produção, consultar o banco pelo hash.
    const session = [...sessions.values()].find(
      (item)=>
        item.refreshTokenHash=== refreshTokenHash&&
        !item.revokedAt
    );

    if (!session) {
      return res.status(401).json({
        error: "Sessão inválida ou expirada."
      });
    }

    if (session.expiresAt<= Date.now()) {
      session.revokedAt= new Date();

      return res.status(401).json({
        error: "Sessão expirada."
      });
    }

    /*
     * Rotação do refresh token:
     * o token anterior deixa de ser válido imediatamente.
     */
    const newRefreshToken = createRefreshToken();

    session.refreshTokenHash= hashToken(newRefreshToken);

    const token = createAccessToken({
      userId: session.userId,
      tenantId: session.tenantId,
      sessionId: session.sessionId
    });

    return res.status(200).json({
      token,
      refreshToken: newRefreshToken
    });
  }catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "Erro interno."
    });
  }
});


/**
 * POST /api/auth/logout
 *
 * Recebe:
 * {
 *   "refreshToken": "..."
 * }
 *
 * Retorna:
 * {
 *   "success": true
 * }
 */
router.post("/logout", async (req, res)=> {
  try {
    const {refreshToken }= req.body;

    if (!refreshToken) {
      return res.status(400).json({
        error: "Refresh token não informado."
      });
    }

    const refreshTokenHash = hashToken(refreshToken);

    const session = [...sessions.values()].find(
      (item)=>
        item.refreshTokenHash=== refreshTokenHash&&
        !item.revokedAt
    );

    // Logout é idempotente: mesmo que a sessão já não exista,
    // não expomos informações sobre ela.
    if (session) {
      session.revokedAt= new Date();
    }

    return res.status(200).json({
      success: true
    });
  }catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "Erro interno."
    });
  }
});

module.exports = router;

const express = require("express");
const sessionRoutes = require("./routes/session");

const app = express();

app.use(express.json());
app.use("/api/auth", sessionRoutes);

app.listen(3000);