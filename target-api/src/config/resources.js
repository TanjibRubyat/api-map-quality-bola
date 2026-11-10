// Single source of truth for the API's resources.
// The server, the data layer, and the spec/ground-truth generator all read
// this, so they can never drift out of sync.
//
// Each resource becomes an endpoint:  GET /api/<name>/{id}
//   vulnerable: true  -> no ownership check (a BOLA flaw)
//   vulnerable: false -> ownership checked (safe)
//
// Two users exist (alice id 1, bob id 2).
//
// ID_MODE (environment variable) controls the shape of the object ids:
//   "seq"  (default) -> small, guessable integers (alice = 1, bob = 2)
//   "spread"         -> integers spread over 2..20, so the tester's typed and
//                       blind guessing budgets give different results
//   "uuid"           -> long, unguessable hex ids, stable across processes
//
// The id MODE is the key experimental knob for "examples". When the map has no
// example id, a tester must guess. Guessing works for "seq" ids and fails for
// "uuid" ids. Both the server and the spec generator import this file, so they
// always agree on the ids.

const crypto = require("crypto");

const ID_MODE = (process.env.ID_MODE || "seq").toLowerCase();
const ID_SALT = process.env.ID_SALT || "apisec-bola-v3";

const NAMES = [
  "orders", "invoices", "messages", "documents",
  "payments", "addresses", "tickets", "bookings",
  "reviews", "notifications", "carts", "wishlists",
  "subscriptions", "transactions", "reports", "files",
  "comments", "sessions", "apikeys", "contacts",
  "events", "tasks", "profiles", "settings",
];

// Deterministic uuid-shaped id from a seed string (stable across node runs).
function uuidFor(seed) {
  const h = crypto.createHash("sha1").update(`${ID_SALT}:${seed}`).digest("hex");
  return [
    h.slice(0, 8), h.slice(8, 12), h.slice(12, 16), h.slice(16, 20), h.slice(20, 32),
  ].join("-");
}

function idFor(resourceName, user /* "alice" | "bob" */, index) {
  if (ID_MODE === "uuid") {
    return uuidFor(`${resourceName}:${user}`);
  }
  if (ID_MODE === "spread") {
    // The attacker's own object stays at 1 so it is always excluded.
    // The victim's object is spread over 2..20, which straddles both of the
    // tester's guessing budgets (GUESS_MAX = 10, BLIND_GUESS_MAX = 5).
    // That is the point of this mode: in "seq" the victim id is always 2, so
    // a typed guess and a blind guess both always succeed and the `examples`
    // and `parameters` dimensions cannot be told apart. In "uuid" neither can
    // ever succeed, so they cannot be told apart either. Here a documented
    // example always finds the object, a typed guess finds it when the id is
    // <= 10, and a blind guess only when the id is <= 5.
    return user === "alice" ? 1 : 2 + (index % 19);
  }
  // "seq": small guessable integers, uniform across resources.
  return user === "alice" ? 1 : 2;
}

// 12 vulnerable, 12 safe, interleaved (even index = vulnerable).
const RESOURCES = NAMES.map((name, i) => ({
  name,
  vulnerable: i % 2 === 0,
  aliceId: idFor(name, "alice", i),
  bobId: idFor(name, "bob", i),
}));

module.exports = { RESOURCES, ID_MODE };
