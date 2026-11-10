// Handles "get one object by id" for every resource.
//
// This is where the deliberate BOLA flaw lives. For a VULNERABLE resource we
// skip the ownership check, so any logged-in user can read anyone's object.
//
// For a SAFE resource, behaviour depends on SAFE_MODE (environment variable):
//   "deny"    (default) -> return 403 when you ask for someone else's object.
//   "owndata"           -> ignore the requested id and return YOUR OWN object
//                          with HTTP 200. This is a real non-vulnerable pattern
//                          (the endpoint always serves the caller's record). It
//                          looks like a 200 "hit", so a tester must inspect the
//                          returned object's owner to avoid a false positive.

const store = require("../data/store");

const SAFE_MODE = (process.env.SAFE_MODE || "deny").toLowerCase();

// Returns an Express handler bound to one resource's config.
function makeGetById(resource) {
  return function getById(req, res) {
    const obj = store.getObject(resource.name, req.params.id);

    if (resource.vulnerable) {
      // BOLA: no ownership check at all.
      if (!obj) return res.status(404).json({ error: "not found" });
      return res.json(obj); // may be another user's object -> the flaw
    }

    // Safe endpoints enforce ownership.
    if (obj && obj.ownerId === req.user.id) {
      return res.json(obj); // the owner reading their own object
    }

    if (SAFE_MODE === "owndata") {
      // Non-vulnerable but noisy: always serve the caller's own object.
      const ownId = store.getOwned(req.user.id)[resource.name];
      const ownObj = store.getObject(resource.name, ownId);
      if (ownObj) return res.json(ownObj); // 200, but NOT a leak
      return res.status(404).json({ error: "not found" });
    }

    // Default "deny" mode.
    if (!obj) return res.status(404).json({ error: "not found" });
    return res.status(403).json({ error: "forbidden" });
  };
}

module.exports = { makeGetById };
