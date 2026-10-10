// Handles login and "who am I" requests.

const users = require("../data/users");
const store = require("../data/store");

function login(req, res) {
  const { username, password } = req.body || {};
  const token = users.verifyCredentials(username, password);
  if (!token) {
    return res.status(401).json({ error: "bad credentials" });
  }
  return res.json({ token });
}

// Returns the current user and the ids of the objects they own.
function me(req, res) {
  const { id, username } = req.user;
  return res.json({ id, username, owns: store.getOwned(id) });
}

module.exports = { login, me };
