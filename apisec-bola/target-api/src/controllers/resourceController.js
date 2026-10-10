// Handles "get one object by id" for every resource.
//
// This is where the deliberate BOLA flaw lives. For a SAFE resource we check
// that the logged-in user owns the object. For a VULNERABLE resource we skip
// that check, so any logged-in user can read anyone's object.

const store = require("../data/store");

// Returns an Express handler bound to one resource's config.
function makeGetById(resource) {
  return function getById(req, res) {
    const obj = store.getObject(resource.name, req.params.id);
    if (!obj) {
      return res.status(404).json({ error: "not found" });
    }
    if (!resource.vulnerable && obj.ownerId !== req.user.id) {
      return res.status(403).json({ error: "forbidden" }); // safe path
    }
    return res.json(obj); // vulnerable resources reach here with no owner check
  };
}

module.exports = { makeGetById };
