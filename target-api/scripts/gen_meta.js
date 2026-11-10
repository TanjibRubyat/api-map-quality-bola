// Generates openapi.json (the full, correct "gold" map) and
// ../../ground_truth.json from the resources list, so the map and the known
// truth always match the API.
//
// The gold map is intentionally RICH: every object endpoint documents its id
// parameter WITH an example, a response schema WITH an example, and a security
// scheme. The experiment then removes these pieces one at a time to measure how
// much each piece of map quality matters to a BOLA tester.
//
// Run from target-api/:            node scripts/gen_meta.js
// For unguessable ids:   ID_MODE=uuid node scripts/gen_meta.js

const fs = require("fs");
const path = require("path");
const { RESOURCES, ID_MODE } = require("../src/config/resources");

const API_DIR = path.join(__dirname, "..");
const PROJECT_DIR = path.join(API_DIR, "..");

// id schema reflects the id mode so a tester can judge whether ids are guessable.
function idSchema() {
  if (ID_MODE === "uuid") return { type: "string", format: "uuid" };
  return { type: "integer", format: "int64" };
}

// --- Static endpoints ---------------------------------------------------
const paths = {
  "/api/login": {
    post: {
      summary: "Log in and receive a bearer token",
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: { username: { type: "string" }, password: { type: "string" } },
              required: ["username", "password"],
            },
            example: { username: "alice", password: "alice123" },
          },
        },
      },
      responses: {
        "200": {
          description: "A bearer token for the authenticated user",
          content: {
            "application/json": {
              schema: { type: "object", properties: { token: { type: "string" } } },
              example: { token: "token-alice" },
            },
          },
        },
      },
    },
  },
  "/api/me": {
    get: {
      summary: "Return the current user and the ids they own",
      security: [{ bearerAuth: [] }],
      responses: {
        "200": {
          description: "The current user",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  id: { type: "integer" },
                  username: { type: "string" },
                  owns: { type: "object" },
                },
              },
              example: { id: 1, username: "alice", owns: {} },
            },
          },
        },
      },
    },
  },
};

// --- Object endpoints (the ones the experiment degrades) ----------------
for (const r of RESOURCES) {
  // The example id is the VICTIM's (bob's) id. A spec-driven tester uses it as
  // the value to request while authenticated as the attacker (alice).
  const objectSchema = {
    type: "object",
    properties: {
      id: idMode_idProp(),
      ownerId: { type: "integer", description: "id of the user who owns this object" },
      data: { type: "string" },
    },
  };
  const objectExample = { id: r.bobId, ownerId: 2, data: `bob ${r.name}` };

  paths[`/api/${r.name}/{id}`] = {
    get: {
      summary: `Get a ${r.name} record by id`,
      security: [{ bearerAuth: [] }],
      parameters: [
        {
          name: "id",
          in: "path",
          required: true,
          description: `The id of the ${r.name} object to fetch`,
          schema: idSchema(),
          example: r.bobId,
        },
      ],
      responses: {
        "200": {
          description: `A ${r.name} object`,
          content: { "application/json": { schema: objectSchema, example: objectExample } },
        },
      },
    },
  };
}

function idMode_idProp() {
  return ID_MODE === "uuid" ? { type: "string", format: "uuid" } : { type: "integer" };
}

const spec = {
  openapi: "3.0.3",
  info: {
    title: "Demo Target API",
    version: "3.0.0",
    description:
      "A deliberately vulnerable API used as a local test target. This is the COMPLETE, correct (gold) map. The experiment degrades copies of it.",
  },
  servers: [{ url: "http://localhost:3000" }],
  components: {
    securitySchemes: {
      bearerAuth: { type: "http", scheme: "bearer", description: "Bearer token from /api/login" },
    },
  },
  // Note: security is declared per-operation (not globally) so the experiment
  // can remove the auth documentation from individual endpoints.
  paths,
};

fs.writeFileSync(path.join(API_DIR, "openapi.json"), JSON.stringify(spec, null, 2));

// --- Build the ground truth --------------------------------------------
const endpoints = {};
for (const r of RESOURCES) {
  endpoints[`GET /api/${r.name}/{id}`] = r.vulnerable;
}

const groundTruth = {
  description:
    "Known truth about the target API. true = this endpoint has a BOLA flaw (no ownership check).",
  id_mode: ID_MODE,
  endpoints,
};

fs.writeFileSync(
  path.join(PROJECT_DIR, "ground_truth.json"),
  JSON.stringify(groundTruth, null, 2)
);

const vulnCount = RESOURCES.filter((r) => r.vulnerable).length;
console.log(`ID_MODE = ${ID_MODE}`);
console.log(`Wrote openapi.json with ${RESOURCES.length} object endpoints (rich gold map).`);
console.log(`Wrote ground_truth.json: ${vulnCount} vulnerable, ${RESOURCES.length - vulnCount} safe.`);
