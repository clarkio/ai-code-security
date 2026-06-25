"use strict";

/**
 * Authentication & authorization middleware.
 *
 * - requireAuth: blocks unauthenticated access to protected routes.
 * - attachUser: loads the current user onto req.user if logged in.
 *
 * Sessions are stored server-side; the cookie only contains an opaque session id.
 */

const repo = require("../db/repository");

function attachUser(req, res, next) {
  if (req.session && req.session.userId) {
    const user = repo.getUserById(req.session.userId);
    if (user) {
      req.user = user;
      res.locals.currentUser = user;
    } else {
      // Stale session — destroy it
      req.session.destroy(() => {});
    }
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) {
    if (req.accepts("html")) {
      return res.redirect("/login");
    }
    return res.status(401).json({ error: "Authentication required" });
  }
  next();
}

module.exports = { attachUser, requireAuth };
