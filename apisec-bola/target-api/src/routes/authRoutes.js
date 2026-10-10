// Routes for login and the current-user endpoint.

const express = require("express");
const { requireAuth } = require("../middleware/auth");
const authController = require("../controllers/authController");

const router = express.Router();

router.post("/login", authController.login);
router.get("/me", requireAuth, authController.me);

module.exports = router;
