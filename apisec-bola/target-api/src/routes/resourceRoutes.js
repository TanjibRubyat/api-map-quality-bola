// Builds one "GET /<resource>/:id" route for every resource in the list.

const express = require("express");
const { RESOURCES } = require("../config/resources");
const { requireAuth } = require("../middleware/auth");
const { makeGetById } = require("../controllers/resourceController");

const router = express.Router();

for (const resource of RESOURCES) {
  router.get(`/${resource.name}/:id`, requireAuth, makeGetById(resource));
}

module.exports = router;
