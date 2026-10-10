// Assembles the Express application: middleware, routes, error handling.
// Kept separate from server.js so the app can be imported for testing.

const express = require("express");
const routes = require("./routes");
const { notFound, errorHandler } = require("./middleware/errorHandler");

const app = express();

app.use(express.json());
app.use(routes);
app.use(notFound);
app.use(errorHandler);

module.exports = app;
