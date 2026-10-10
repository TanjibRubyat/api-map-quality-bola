// Generates openapi.json (the full, correct map) and ../ground_truth.json
// from resources.js, so the map and the known truth always match the server.
//
// Run:  node gen_meta.js

const fs = require("fs");
const path = require("path");
const { RESOURCES } = require("./resources");

// --- Build the OpenAPI map ---------------------------------------------
const paths = {
  "/api/login": {
    post: {
      summary: "Log in and receive a token",
      responses: { "200": { description: "token" } },
    },
  },
  "/api/me": {
    get: {
      summary: "Return the current user and the ids they own",
      responses: { "200": { description: "ok" } },
    },
  },
};

for (const r of RESOURCES) {
  paths[`/api/${r.name}/{id}`] = {
    get: {
      summary: `Get a ${r.name} record by id`,
      parameters: [
        { name: "id", in: "path", required: true, schema: { type: "integer" } },
      ],
      responses: { "200": { description: "ok" } },
    },
  };
}

const spec = {
  openapi: "3.0.3",
  info: {
    title: "Demo Target API",
    version: "2.0.0",
    description:
      "A deliberately vulnerable API used as a local test target. This is the COMPLETE, correct map. The experiment damages copies of it.",
  },
  servers: [{ url: "http://localhost:3000" }],
  paths,
};

fs.writeFileSync(
  path.join(__dirname, "openapi.json"),
  JSON.stringify(spec, null, 2)
);

// --- Build the ground truth --------------------------------------------
const endpoints = {};
for (const r of RESOURCES) {
  endpoints[`GET /api/${r.name}/{id}`] = r.vulnerable;
}

const groundTruth = {
  description:
    "Known truth about the target API. true = this endpoint has a BOLA flaw (no ownership check).",
  endpoints,
};

fs.writeFileSync(
  path.join(__dirname, "..", "ground_truth.json"),
  JSON.stringify(groundTruth, null, 2)
);

const vulnCount = RESOURCES.filter((r) => r.vulnerable).length;
console.log(`Wrote openapi.json with ${RESOURCES.length} object endpoints.`);
console.log(`Wrote ground_truth.json: ${vulnCount} vulnerable, ${RESOURCES.length - vulnCount} safe.`);
