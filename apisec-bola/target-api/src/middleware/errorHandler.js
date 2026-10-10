// Shared 404 and error handling, kept in one place.

function notFound(req, res) {
  res.status(404).json({ error: "route not found" });
}

// Express error handler (four arguments).
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  console.error(err);
  res.status(500).json({ error: "internal server error" });
}

module.exports = { notFound, errorHandler };
