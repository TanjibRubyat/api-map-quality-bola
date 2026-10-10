// In-memory user records and credentials.
// In a real system these would be a database table with hashed passwords.

// token -> user. In a real app these would be signed JWTs.
const USERS_BY_TOKEN = {
  "token-alice": { id: 1, username: "alice" },
  "token-bob": { id: 2, username: "bob" },
};

const PASSWORDS = { alice: "alice123", bob: "bob123" };
const TOKEN_FOR = { alice: "token-alice", bob: "token-bob" };

function findByToken(token) {
  return USERS_BY_TOKEN[token] || null;
}

function verifyCredentials(username, password) {
  if (PASSWORDS[username] && PASSWORDS[username] === password) {
    return TOKEN_FOR[username];
  }
  return null;
}

module.exports = { findByToken, verifyCredentials };
