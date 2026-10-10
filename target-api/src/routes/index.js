// Mounts all route groups under /api.

const express = require("express");
const authRoutes = require("./authRoutes");
const resourceRoutes = require("./resourceRoutes");

const router = express.Router();

router.use("/api", authRoutes);
router.use("/api", resourceRoutes);

module.exports = router;
