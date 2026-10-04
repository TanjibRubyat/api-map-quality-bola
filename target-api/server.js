// Deliberately vulnerable demo API for MSc project.
// Purpose: a safe, legal, local target for measuring how BOLA detection
// changes as the OpenAPI "map" becomes less accurate.
//
// It contains some endpoints with a BOLA flaw (no ownership check) and
// some safe endpoints (proper ownership check). Two users exist: alice and bob.
//
// DO NOT deploy this on the public internet. It is insecure on purpose.

const express = require("express");
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// --- Fake users ---------------------------------------------------------
// token -> userId. In a real app these would be signed JWTs.
const USERS = {
  "token-alice": { id: 1, username: "alice" },
  "token-bob": { id: 2, username: "bob" },
};

const PASSWORDS = { alice: "alice123", bob: "bob123" };
const TOKEN_FOR = { alice: "token-alice", bob: "token-bob" };

// --- Fake data, each record owned by a user -----------------------------
// ids are chosen so each user clearly owns different objects.
const orders = {
  1001: { id: 1001, ownerId: 1, item: "Keyboard", total: 45 },      // alice
  2001: { id: 2001, ownerId: 2, item: "Monitor", total: 180 },      // bob
};
const invoices = {
  1002: { id: 1002, ownerId: 1, amount: 300 },                      // alice
  2002: { id: 2002, ownerId: 2, amount: 520 },                      // bob
};
const messages = {
  1003: { id: 1003, ownerId: 1, text: "alice private note" },      // alice
  2003: { id: 2003, ownerId: 2, text: "bob private note" },        // bob
};
const documents = {
  1004: { id: 1004, ownerId: 1, title: "alice CV" },               // alice
  2004: { id: 2004, ownerId: 2, title: "bob CV" },                 // bob
};
const profiles = {
  1: { userId: 1, fullName: "Alice Smith", email: "alice@example.com" },
  2: { userId: 2, fullName: "Bob Jones", email: "bob@example.com" },
};
const settings = {
  1: { userId: 1, theme: "dark", twoFactor: true },
  2: { userId: 2, theme: "light", twoFactor: false },
};

// Which object each user owns, used by the tester to bootstrap known ids.
const OWNED = {
  1: { orderId: 1001, invoiceId: 1002, messageId: 1003, documentId: 1004 },
  2: { orderId: 2001, invoiceId: 2002, messageId: 2003, documentId: 2004 },
};

// --- Auth helper --------------------------------------------------------
function currentUser(req) {
  const auth = req.headers["authorization"] || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  return USERS[token] || null;
}

function requireAuth(req, res) {
  const user = currentUser(req);
  if (!user) {
    res.status(401).json({ error: "unauthenticated" });
    return null;
  }
  return user;
}

// --- Login --------------------------------------------------------------
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (PASSWORDS[username] && PASSWORDS[username] === password) {
    return res.json({ token: TOKEN_FOR[username] });
  }
  return res.status(401).json({ error: "bad credentials" });
});

// whoami: lets a client learn the ids of the objects it owns.
app.get("/api/me", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  res.json({ id: user.id, username: user.username, owns: OWNED[user.id] });
});

// --- Object-level endpoints --------------------------------------------
// VULNERABLE: returns the object without checking who owns it (BOLA).
app.get("/api/orders/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const obj = orders[req.params.id];
  if (!obj) return res.status(404).json({ error: "not found" });
  return res.json(obj); // no ownership check -> BOLA
});

// VULNERABLE
app.get("/api/invoices/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const obj = invoices[req.params.id];
  if (!obj) return res.status(404).json({ error: "not found" });
  return res.json(obj); // no ownership check -> BOLA
});

// VULNERABLE
app.get("/api/messages/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const obj = messages[req.params.id];
  if (!obj) return res.status(404).json({ error: "not found" });
  return res.json(obj); // no ownership check -> BOLA
});

// SAFE: checks that the logged-in user owns the object.
app.get("/api/documents/:id", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const obj = documents[req.params.id];
  if (!obj) return res.status(404).json({ error: "not found" });
  if (obj.ownerId !== user.id) return res.status(403).json({ error: "forbidden" });
  return res.json(obj); // ownership checked -> safe
});

// SAFE
app.get("/api/users/:id/profile", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (Number(req.params.id) !== user.id) return res.status(403).json({ error: "forbidden" });
  const obj = profiles[req.params.id];
  if (!obj) return res.status(404).json({ error: "not found" });
  return res.json(obj); // ownership checked -> safe
});

// SAFE
app.get("/api/users/:id/settings", (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (Number(req.params.id) !== user.id) return res.status(403).json({ error: "forbidden" });
  const obj = settings[req.params.id];
  if (!obj) return res.status(404).json({ error: "not found" });
  return res.json(obj); // ownership checked -> safe
});

app.listen(PORT, () => {
  console.log(`Target API listening on http://localhost:${PORT}`);
});
