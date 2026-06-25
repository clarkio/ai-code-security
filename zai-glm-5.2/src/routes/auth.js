"use strict";

/**
 * Auth routes: register, login, logout.
 *
 * SECURITY:
 *  - Auth endpoints have a stricter rate limit (brute-force protection).
 *  - Passwords are hashed with bcrypt before storage.
 *  - On login failure we return a generic message (no user enumeration).
 *  - Session is regenerated on login to prevent session fixation.
 */

const express = require("express");

const router = express.Router();
const repo = require("../db/repository");
const { hashPassword, verifyPassword } = require("../utils/password");
const {
  registerRules,
  loginRules,
  handleValidationErrors,
} = require("../middleware/validation");
const { authLimiter } = require("../config/security");

// --- Register ---
router.post(
  "/register",
  authLimiter,
  registerRules,
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { username, password } = req.body;

      // Prevent duplicate usernames (no enumeration: same error either way)
      if (repo.getUserByUsername(username)) {
        return res.status(409).json({ error: "Registration failed" });
      }

      const hash = await hashPassword(password);
      const userId = repo.createUser(username, hash);

      // Regenerate session to prevent fixation
      req.session.regenerate((err) => {
        if (err) return next(err);
        req.session.userId = userId;
        return res.status(201).json({ message: "Account created", userId });
      });
    } catch (err) {
      next(err);
    }
  },
);

// --- Login ---
router.post(
  "/login",
  authLimiter,
  loginRules,
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { username, password } = req.body;
      const user = repo.getUserByUsername(username);

      // Generic error to prevent user enumeration
      const genericError = { error: "Invalid username or password" };

      if (!user) {
        // Still do a bcrypt compare to keep timing similar
        await verifyPassword(
          password,
          "$2b$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvali",
        );
        return res.status(401).json(genericError);
      }

      const valid = await verifyPassword(password, user.password_hash);
      if (!valid) {
        return res.status(401).json(genericError);
      }

      // Regenerate session to prevent session fixation
      req.session.regenerate((err) => {
        if (err) return next(err);
        req.session.userId = user.id;
        return res.json({ message: "Logged in", userId: user.id });
      });
    } catch (err) {
      next(err);
    }
  },
);

// --- Logout ---
router.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: "Logout failed" });
    res.clearCookie("connect.sid");
    return res.json({ message: "Logged out" });
  });
});

module.exports = router;
