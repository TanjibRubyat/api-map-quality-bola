// Entry point. Its only job is to start the server.
//
// DO NOT deploy on the public internet. This API is insecure on purpose:
// it is a local test target for the MSc project experiment.

const app = require("./src/app");
const { PORT } = require("./src/config");
const { RESOURCES } = require("./src/config/resources");

app.listen(PORT, () => {
  console.log(`Target API listening on http://localhost:${PORT}`);
  console.log(`Endpoints: ${RESOURCES.length} object-level (plus /api/login and /api/me)`);
});
