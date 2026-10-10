// Authentication middleware.
// Reads the Bearer token, looks up the user, and attaches it to req.user.
// If there is no valid token, it stops the request with 401.

const users = require("../data/users");

function requireAuth(req, res, next) {
  const header = req.headers["authorization"] || "";
  const token = header.replace(/^Bearer\s+/i, "").trim();
  const user = users.findByToken(token);
  if (!user) {
    return res.status(401).json({ error: "unauthenticated" });
  }
  req.user = user;
  next();
}

module.exports = { requireAuth };
