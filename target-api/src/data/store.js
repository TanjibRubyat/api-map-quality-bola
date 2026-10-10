// In-memory data store, built from the resources list.
// Acts as the "model" layer: the rest of the app reads data only through here.

const { RESOURCES } = require("../config/resources");

// store[resourceName][objectId] = { id, ownerId, data }
const store = {};
// owned[userId] = { resourceName: objectId }
const owned = { 1: {}, 2: {} };

for (const r of RESOURCES) {
  store[r.name] = {
    [r.aliceId]: { id: r.aliceId, ownerId: 1, data: `alice ${r.name}` },
    [r.bobId]: { id: r.bobId, ownerId: 2, data: `bob ${r.name}` },
  };
  owned[1][r.name] = r.aliceId;
  owned[2][r.name] = r.bobId;
}

function getObject(resourceName, id) {
  const collection = store[resourceName];
  return collection ? collection[id] || null : null;
}

function getOwned(userId) {
  return owned[userId] || {};
}

module.exports = { getObject, getOwned };
