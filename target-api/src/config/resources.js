// Single source of truth for the API's resources.
// The server, the data layer, and the spec/ground-truth generator all read
// this, so they can never drift out of sync.
//
// Each resource becomes an endpoint:  GET /api/<name>/{id}
//   vulnerable: true  -> no ownership check (a BOLA flaw)
//   vulnerable: false -> ownership checked (safe)
//
// Two users exist (alice id 1, bob id 2). For resource index i:
//   alice's object id = (i+1)*100 + 1
//   bob's   object id = (i+1)*100 + 2

const NAMES = [
  "orders", "invoices", "messages", "documents",
  "payments", "addresses", "tickets", "bookings",
  "reviews", "notifications", "carts", "wishlists",
  "subscriptions", "transactions", "reports", "files",
  "comments", "sessions", "apikeys", "contacts",
  "events", "tasks", "profiles", "settings",
];

// 12 vulnerable, 12 safe, interleaved (even index = vulnerable).
const RESOURCES = NAMES.map((name, i) => ({
  name,
  vulnerable: i % 2 === 0,
  aliceId: (i + 1) * 100 + 1,
  bobId: (i + 1) * 100 + 2,
}));

module.exports = { RESOURCES };
