const express = require("express");
const jwt = require("jsonwebtoken");

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

router.post("/auth/refresh", async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ error: "Refresh token obrigatório" });
  }

  try {
    const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);

    const token = jwt.sign(
      {
        userId: payload.userId,
        tenantId: payload.tenantId
      },
      JWT_SECRET,
      { expiresIn: "15m" }
    );

    return res.status(200).json({ token });
  } catch {
    return res.status(401).json({ error: "Refresh token inválido ou expirado" });
  }
});

router.post("/auth/logout", async (req, res) => {
  // O middleware de autenticação deve disponibilizar req.user.
  // Em uma implementação real, invalide o refresh token no banco/cache.
  return res.status(200).json({
    success: true,
    message: "Sessão encerrada com sucesso"
  });
});

module.exports = router;
